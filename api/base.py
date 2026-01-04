# -*- coding: utf-8 -*-
import functools
import random
import re
import threading
import time
from enum import Enum
from hashlib import md5
from typing import Self, Optional, Literal

import requests
from loguru import logger
from requests import RequestException
from requests.adapters import HTTPAdapter
from tqdm import tqdm

from api.answer import *
from api.answer_check import cut
from api.cipher import AESCipher
from api.config import GlobalConst as gc
from api.cookies import save_cookies, use_cookies
from api.decode import (
    decode_course_list,
    decode_course_point,
    decode_course_card,
    decode_course_folder,
    decode_questions_info,
)
from api.exceptions import MaxRetryExceeded


def get_timestamp():
    return str(int(time.time() * 1000))


class SessionManager:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self._session = requests.Session()
        self._session.mount("https://", HTTPAdapter(max_retries=10))
        self._session.mount("http://", HTTPAdapter(max_retries=10))
        self._session.request = functools.partial(self._session.request, timeout=5)
        # For debug purposes
        # self._session.verify=False
        self._session.headers.clear()
        self._session.headers.update(gc.HEADERS)
        self._session.cookies.update(use_cookies())

    @classmethod
    def get_instance(cls) -> Self:
        return cls()

    @classmethod
    def get_session(cls) -> requests.Session:
        instance = cls.get_instance()
        return instance._session

    @classmethod
    def update_cookies(cls):
        cls.get_instance()._session.cookies.update(use_cookies())


class Account:
    username = None
    password = None
    last_login = None
    isSuccess = None

    def __init__(self, _username, _password):
        self.username = _username
        self.password = _password


class RateLimiter:
    def __init__(self, call_interval):
        self.last_call = time.time()
        self.lock = threading.Lock()
        self.call_interval = call_interval

    def limit_rate(self, random_time=False, random_min=0.0, random_max=1.0):
        with self.lock:
            if random_time:
                wait_time = random.uniform(random_min, random_max)
                time.sleep(wait_time)
            now = time.time()
            time_elapsed = now - self.last_call
            if time_elapsed <= self.call_interval:
                time.sleep(self.call_interval - time_elapsed)
                self.last_call = time.time()
                return

            self.last_call = now
            return


class StudyResult(Enum):
    SUCCESS = 0
    FORBIDDEN = 1  # 403
    ERROR = 2
    TIMEOUT = 3

    def is_success(self):
        return self == StudyResult.SUCCESS
    def is_failure(self):
        return self != StudyResult.SUCCESS

class Chaoxing:
    def __init__(self, account: Account = None, tiku: Tiku = None, **kwargs):
        self.account = account
        self.cipher = AESCipher()
        self.tiku = tiku
        self.kwargs = kwargs
        self.rollback_times = 0
        self.rate_limiter = RateLimiter(0.5) # 其他接口速率限制比较松
        self.video_log_limiter = RateLimiter(2) # 上报进度极其容易卡验证码，限制2s一次

    def login(self, login_with_cookies=False):
        if login_with_cookies:
            logger.info("Logging in with cookies")
            SessionManager.update_cookies()
            logger.debug(f"Logged in with cookies: {SessionManager.get_instance()._session.cookies}")
            if not self._validate_cookie_session():
                logger.warning("Cookie 登录校验失败，尝试使用账号密码重新登录")
                if self.account and self.account.username and self.account.password:
                    return self.login(login_with_cookies=False)
                return {"status": False, "msg": "cookies 已失效，请更新 cookies 或提供账号密码"}
            logger.info("🎉 登录成功!")
            return {"status": True, "msg": "登录成功"}

        _session = requests.Session()
        _url = "https://passport2.chaoxing.com/fanyalogin"
        _data = {
            "fid": "-1",
            "uname": self.cipher.encrypt(self.account.username),
            "password": self.cipher.encrypt(self.account.password),
            "refer": "https%3A%2F%2Fi.chaoxing.com",
            "t": True,
            "forbidotherlogin": 0,
            "validate": "",
            "doubleFactorLogin": 0,
            "independentId": 0,
        }
        logger.trace("正在尝试登录...")
        resp = _session.post(_url, headers=gc.HEADERS, data=_data)
        if resp and resp.json()["status"] == True:
            save_cookies(_session)
            SessionManager.update_cookies()
            logger.info("🎉 登录成功!")
            return {"status": True, "msg": "登录成功"}
        else:
            return {"status": False, "msg": str(resp.json()["msg2"])}

    def _validate_cookie_session(self) -> bool:
        session = SessionManager.get_instance()._session
        if not session.cookies.get("_uid"):
            return False

        test_session = requests.Session()
        test_session.headers.update(gc.HEADERS)
        test_session.cookies.update(session.cookies.get_dict())

        try:
            resp = test_session.post(
                "https://mooc2-ans.chaoxing.com/mooc2-ans/visit/courselistdata",
                data={"courseType": 1, "courseFolderId": 0, "query": "", "superstarClass": 0},
                timeout=8,
            )
        except RequestException as exc:
            logger.debug("Cookie validation request failed: {}", exc)
            return False

        if resp.status_code != 200:
            return False

        if "passport2.chaoxing.com" in resp.text or "login" in resp.text.lower():
            return False

        return True

    def get_fid(self):
        _session = SessionManager.get_session()
        return _session.cookies.get("fid")

    def get_uid(self):
        s = SessionManager.get_session()
        if "_uid" in s.cookies:
            return s.cookies["_uid"]
        if "UID" in s.cookies:
            return s.cookies["UID"]
        raise ValueError("Cannot get uid !")

    def get_course_list(self):
        _session = SessionManager.get_session()
        _url = "https://mooc2-ans.chaoxing.com/mooc2-ans/visit/courselistdata"
        _data = {"courseType": 1, "courseFolderId": 0, "query": "", "superstarClass": 0}
        logger.trace("正在读取所有的课程列表...")

        # 接口突然抽风, 增加headers
        # 有可能只是referer的问题
        _headers = {
            "Referer": "https://mooc2-ans.chaoxing.com/mooc2-ans/visit/interaction?moocDomain=https://mooc1-1.chaoxing.com/mooc-ans",
        }
        _resp = _session.post(_url, headers=_headers, data=_data)
        # logger.trace(f"原始课程列表内容:\n{_resp.text}")
        logger.debug("课程列表读取完毕...")
        course_list = decode_course_list(_resp.text)

        _interaction_url = "https://mooc2-ans.chaoxing.com/mooc2-ans/visit/interaction"
        _interaction_resp = _session.get(_interaction_url)
        course_folder = decode_course_folder(_interaction_resp.text)
        for folder in course_folder:
            _data = {
                "courseType": 1,
                "courseFolderId": folder["id"],
                "query": "",
                "superstarClass": 0,
            }
            _resp = _session.post(_url, data=_data)
            course_list += decode_course_list(_resp.text)
            
        # 尝试获取精准的进度信息 (基于 HAR 抓包分析)
        if course_list:
            logger.debug("正在同步精准进度信息...")
            course_list = self.get_course_progress(course_list)
            
        return course_list

    def get_course_progress(self, course_list):
        """
        通过 stu-job-info 接口获取精准的课程进度
        """
        if not course_list:
            return course_list
            
        _session = SessionManager.get_session()
        # 构建 clazzPersonStr 格式: clazzId_cpi,clazzId_cpi...
        clazz_person_list = []
        for course in course_list:
            if "clazzId" in course and "cpi" in course:
                clazz_person_list.append(f"{course['clazzId']}_{course['cpi']}")
        
        if not clazz_person_list:
            return course_list
            
        clazz_person_str = ",".join(clazz_person_list)
        _url = "https://mooc2-ans.chaoxing.com/mooc2-ans/mycourse/stu-job-info"
        _params = {"clazzPersonStr": clazz_person_str}
        
        try:
            # 增加 Referer 模拟真实请求
            _headers = {
                "Referer": "https://mooc2-ans.chaoxing.com/visit/interaction",
                "X-Requested-With": "XMLHttpRequest"
            }
            _resp = _session.get(_url, params=_params, headers=_headers)
            _json = _resp.json()
            if _json.get("status"):
                job_array = _json.get("jobArray", [])
                # 创建 clazzId 到 progress 的映射
                progress_map = {}
                for job in job_array:
                    clazz_id = str(job["clazzId"])
                    if job.get("jobCount", 0) > 0:
                        progress_map[clazz_id] = f"{int(job['jobRate'])}%"
                    else:
                        progress_map[clazz_id] = "无任务"
                
                # 更新 course_list 中的进度
                for course in course_list:
                    clazz_id = str(course["clazzId"])
                    if clazz_id in progress_map:
                        course["progress"] = progress_map[clazz_id]
                    else:
                        # 如果接口没返回该课程，通常也是没有任务点
                        course["progress"] = "无任务"
                        logger.trace(f"课程 [{course['title']}] 未在进度接口中返回，标记为: 无任务")
        except Exception as e:
            logger.debug(f"获取课程精准进度失败: {e} (将保留原始解析结果)")
            
        return course_list

    def get_course_point(self, _courseid, _clazzid, _cpi):
        _session = SessionManager.get_session()
        _url = f"https://mooc2-ans.chaoxing.com/mooc2-ans/mycourse/studentcourse?courseid={_courseid}&clazzid={_clazzid}&cpi={_cpi}&ut=s"
        logger.trace("开始读取课程所有章节...")
        _resp = _session.get(_url)
        # logger.trace(f"原始章节列表内容:\n{_resp.text}")
        logger.debug("课程章节读取成功...")
        return decode_course_point(_resp.text)

    def get_job_list(self, course: dict, point: dict) -> tuple[list[dict], dict]:
        _session = SessionManager.get_session()
        self.rate_limiter.limit_rate()
        job_list = []
        job_info = {}
        cards_params = {
            "clazzid": course["clazzId"],
            "courseid": course["courseId"],
            "knowledgeid": point["id"],
            "ut": "s",
            "cpi": course["cpi"],
            "v": "2025-0424-1038-3",
            "mooc2": 1
        }

        # 学习界面任务卡片数, 很少有3个的, 但是对于章节解锁任务点少一个都不行, 可以从API /mooc-ans/mycourse/studentstudyAjax获取值, 或者干脆直接加, 但二者都会造成额外的请求
        for _possible_num in "0123456":

            logger.trace("开始读取章节所有任务点...")

            cards_params.update({"num": _possible_num})
            _resp = _session.get("https://mooc1.chaoxing.com/mooc-ans/knowledge/cards", params=cards_params)
            if _resp.status_code != 200:
                logger.error(f"未知错误: {_resp.status_code} 正在跳过")
                logger.error(_resp.text)
                return [], {}

            _job_list, _job_info = decode_course_card(_resp.text)
            if _job_info.get("notOpen", False):
                # 直接返回, 节省一次请求
                logger.info("该章节未开放")
                return [], _job_info

            job_list += _job_list
            job_info.update(_job_info)

        if not job_list:
            self.study_emptypage(course, point)
        # logger.trace(f"原始任务点列表内容:\n{_resp.text}")
        logger.debug("章节任务点读取成功...")

        return job_list, job_info

    def get_enc(self, clazzId, jobid, objectId, playingTime, duration, userid):
        return md5(
            f"[{clazzId}][{userid}][{jobid}][{objectId}][{playingTime * 1000}][d_yHJ!$pdA~5][{duration * 1000}][0_{duration}]".encode()
        ).hexdigest()

    def video_progress_log(
            self,
            _session,
            _course,
            _job,
            _job_info,
            _dtoken,
            _duration,
            _playingTime,
            _type: str = "Video",
            headers: Optional[dict] = None,
    ) -> tuple[bool, int]:

        if headers is None:
            logger.warning("null headers")
            headers = gc.VIDEO_HEADERS

        self.video_log_limiter.limit_rate(random_time=True, random_max=2)

        if "courseId" in _job["otherinfo"]:
            logger.error(_job["otherinfo"])
            raise RuntimeError("this is not possible")

        enc = self.get_enc(_course["clazzId"], _job["jobid"], _job["objectid"], _playingTime, _duration, self.get_uid())
        params = {
            "clazzId": _course["clazzId"],
            "playingTime": _playingTime,
            "duration": _duration,
            "clipTime": f"0_{_duration}",
            "objectId": _job["objectid"],
            "otherInfo": _job["otherinfo"],
            "courseId": _course["courseId"],
            "jobid": _job["jobid"],
            "userid": self.get_uid(),
            "isdrag": "3",
            "view": "pc",
            "enc": enc,
            "dtype": _type
        }

        _url = (
            f"https://mooc1.chaoxing.com/mooc-ans/multimedia/log/a/"
            f"{_course['cpi']}/"
            f"{_dtoken}"
        )


        face_capture_enc = _job["videoFaceCaptureEnc"]
        att_duration = _job["attDuration"]
        att_duration_enc = _job["attDurationEnc"]

        if face_capture_enc:
            params["videoFaceCaptureEnc"] = face_capture_enc
        if att_duration:
            params["attDuration"] = att_duration
        if att_duration_enc:
            params["attDurationEnc"] = att_duration_enc

        rt = _job['rt']
        if not rt:
            rt_search = re.search(r"-rt_([1d])", _job['otherinfo'])
            if rt_search:
                rt_char = rt_search.group(1)
                rt = "0.9" if rt_char == "d" else "1"
                logger.trace(f"Got rt from otherinfo: {rt}")

        if rt:
            logger.trace(f"Got rt: {rt}")
            params.update({"rt": rt,
                           "_t": get_timestamp()})
            resp = _session.get(_url, params=params, headers=headers)
        else:
            logger.warning("Failed to get rt")
            for rt in [0.9, 1]:
                params.update({"rt": rt,
                               "_t": get_timestamp()})
                resp = _session.get(_url, params=params, headers=headers)
                if resp.status_code == 200:
                    logger.trace(resp.text)
                    return resp.json()["isPassed"], 200
                #elif resp.ok:
                #    # TODO: 处理验证码
                #    pass
                elif resp.status_code == 403:
                    logger.warning("出现403报错, 正常尝试切换rt")

                else:
                    logger.warning("未知错误 jobid={}, status_code={}, 摘要:\n{}",
                                   _job.get("jobid"),
                                   resp.status_code,
                                   resp.text[:200]
                    )
                    break

        if resp.status_code == 200:
            logger.trace(resp.text)
            return resp.json()["isPassed"], 200

        elif resp.status_code == 403:
            logger.debug(
                "视频进度上报返回403, jobid={}, 摘要={}",
                _job.get("jobid"),
                resp.text[:200],
            )

            # 若出现两个rt参数都返回403的情况, 则跳过当前任务
            logger.error("出现403报错, 尝试修复无效, 正在跳过当前任务点...")
            logger.error("请求url: {}", resp.url)
            logger.error("请求头: {}", dict(_session.headers) | headers)
            return False, 403

        logger.error(f"未知错误: {resp.status_code}")
        logger.error("请求url:", resp.url)
        logger.error("请求头：", dict(_session.headers) | headers)
        return False, resp.status_code


    def _refresh_video_status(self, session: requests.Session, job: dict, _type: Literal["Video", "Audio"]) -> Optional[dict]:
        self.rate_limiter.limit_rate(random_time=True, random_max=0.2)
        headers = gc.VIDEO_HEADERS if _type == "Video" else gc.AUDIO_HEADERS
        info_url = (
            f"https://mooc1.chaoxing.com/ananas/status/{job['objectid']}?"
            f"k={self.get_fid()}&flag=normal"
        )
        try:
            resp = session.get(info_url, timeout=8, headers=headers)
        except RequestException as exc:
            logger.debug("刷新视频状态失败: {}", exc)
            return None

        if resp.status_code != 200:
            logger.debug("刷新视频状态返回码异常: {}"% resp.status_code)
            logger.debug(resp.text)
            return None

        try:
            data = resp.json()
        except ValueError as exc:
            logger.debug("解析视频状态响应失败: {}", exc)
            return None

        if data.get("status") == "success":
            return data

        return None

    def _recover_after_forbidden(self, session: requests.Session, job: dict, _type: Literal["Video", "Audio"]):
        SessionManager.update_cookies()
        refreshed = self._refresh_video_status(session, job, _type)
        if refreshed:
            return refreshed

        # FIXME: Temporarily disabled for multithreading support
        if False and self.account and self.account.username and self.account.password:
            login_result = self.login(login_with_cookies=False)
            if login_result.get("status"):
                SessionManager.update_cookies()
                return self._refresh_video_status(session, job, _type)
            logger.warning("账号密码登录失败: {}", login_result.get("msg"))

        return None


    def study_video(self, _course, _job, _job_info, _speed: float = 1.0, _type: Literal["Video", "Audio"] = "Video") -> StudyResult:
        _session = SessionManager.get_session()

        headers = gc.VIDEO_HEADERS if _type == "Video" else gc.AUDIO_HEADERS
        _info_url = f"https://mooc1.chaoxing.com/ananas/status/{_job['objectid']}?k={self.get_fid()}&flag=normal"
        _video_info = _session.get(_info_url, headers=headers).json()

        if _video_info["status"] != "success":
            logger.error(f"Unknown status: {_video_info['status']}")
            return StudyResult.ERROR

        _dtoken = _video_info["dtoken"]

        _crc = _video_info["crc"]
        _key = _video_info["key"]

        # Time in the real world: last_iter, gc.THRESHOLD
        # Time in the video (can be scaled with the speed factor): duration, play_time, last_log_time, wait_time

        duration = int(_video_info["duration"])
        play_time = int(_job["playTime"]) // 1000
        last_log_time = 0
        last_iter = time.time()
        wait_time = int(random.uniform(30, 90))

        logger.debug(f"开始任务: {_job['name']}, 总时长: {duration}s, 已进行: {play_time}s")

        pbar = tqdm(total=duration, initial=play_time, desc=_job["name"][:20],
                    unit_scale=True, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')

        forbidden_retry = 0
        max_forbidden_retry = 2

        passed, state = self.video_progress_log(_session, _course, _job, _job_info, _dtoken, duration, play_time, _type,headers=headers)
        passed, state = self.video_progress_log(_session, _course, _job, _job_info, _dtoken, duration, duration, _type, headers=headers)

        if passed:
            logger.info("任务瞬间完成: {}", _job['name'])
            return StudyResult.SUCCESS

        while not passed:
            # Sometimes the last request needs to be sent several times to complete the task
            if play_time - last_log_time >= wait_time or play_time == duration:

                passed, state = self.video_progress_log(_session, _course, _job, _job_info, _dtoken, duration,
                                                        int(play_time), _type, headers=headers)

                if state == 403:
                    if forbidden_retry >= max_forbidden_retry:
                        logger.warning("403重试失败, 跳过当前任务")
                        return StudyResult.FORBIDDEN
                    forbidden_retry += 1
                    logger.warning(
                        "出现403报错, 正在尝试刷新会话状态 (第{}次)",
                        forbidden_retry,
                    )
                    time.sleep(random.uniform(2, 4))
                    refreshed_meta = self._recover_after_forbidden(_session, _job, _type)
                    if refreshed_meta:
                        # FIXME: Maybe it should be considered an error if those keys aren't present in the refreshed meta, so we perhaps shouldn't use get()
                        _dtoken = refreshed_meta.get("dtoken", _dtoken)
                        _duration = refreshed_meta.get("duration", duration)
                        play_time = refreshed_meta.get("playTime", play_time)

                        logger.debug("Refreshed token: {}, duration: {}, play time: {}", _dtoken, _duration, play_time)
                        continue

                elif not passed and state != 200:
                    return StudyResult.ERROR




                wait_time = int(random.uniform(30, 90))
                last_log_time = play_time

            dt = (time.time() - last_iter) * _speed # Since uploading the progress takes time, we assume that the video is still playing in the background, so manually calculate the time elapsed is required
            last_iter = time.time()
            play_time = min(duration, play_time+dt)

            pbar.n = int(play_time)
            pbar.refresh()
            time.sleep(gc.THRESHOLD)

        logger.info("任务完成: {}", _job['name'])
        return StudyResult.SUCCESS

    def study_document(self, _course, _job) -> StudyResult:
        """
        Study a document in Chaoxing platform.

        This method makes a GET request to fetch document information for a given course and job.

        Args:
            _course (dict): Dictionary containing course information with keys:
                - courseId: ID of the course
                - clazzId: ID of the class
            _job (dict): Dictionary containing job information with keys:
                - jobid: ID of the job
                - otherinfo: String containing node information
                - jtoken: Authentication token for the job

        Returns:
            requests.Response: Response object from the GET request

        Note:
            This method requires the following helper functions:
            - init_session(): To initialize a new session
            - get_timestamp(): To get current timestamp
            - re module for regular expression matching
        """
        _session = SessionManager.get_session()
        _url = f"https://mooc1.chaoxing.com/ananas/job/document?jobid={_job['jobid']}&knowledgeid={re.findall(r'nodeId_(.*?)-', _job['otherinfo'])[0]}&courseid={_course['courseId']}&clazzid={_course['clazzId']}&jtoken={_job['jtoken']}&_dc={get_timestamp()}"
        _resp = _session.get(_url)
        if _resp.status_code != 200:
            return StudyResult.ERROR
        else:
            return StudyResult.SUCCESS

    def study_work(self, _course, _job, _job_info) -> StudyResult:
        # FIXME: 这一块可以单独搞一个类出来了，方法里面又套方法，每一次调用都会创建新的方法，十分浪费
        if self.tiku.DISABLE or not self.tiku:
            logger.warning("未配置题库或题库已禁用，无法自动完成章节测验任务。")
            return StudyResult.ERROR
        _ORIGIN_HTML_CONTENT = ""  # 用于配合输出网页源码, 帮助修复#391错误

        def random_answer(options: str) -> str:
            answer = ""
            if not options:
                return answer

            if q["type"] == "multiple":
                logger.debug(f"当前选项列表[cut前] -> {options}")
                _op_list = multi_cut(options)
                logger.debug(f"当前选项列表[cut后] -> {_op_list}")

                if not _op_list:
                    logger.error(
                        "选项为空, 未能正确提取题目选项信息! 请反馈并提供以上信息"
                    )
                    return answer

                available_options = len(_op_list)
                select_count = 0

                # 根据可用选项数量调整可能选择的选项数
                if available_options <= 1:
                    select_count = available_options
                else:
                    max_possible = min(4, available_options)
                    min_possible = min(2, available_options)

                    weights_map = {
                        2: [1.0],
                        3: [0.3, 0.7],
                        4: [0.1, 0.5, 0.4],
                        5: [0.1, 0.4, 0.3, 0.2],
                    }

                    weights = weights_map.get(max_possible, [0.3, 0.4, 0.3])
                    possible_counts = list(range(min_possible, max_possible + 1))

                    weights = weights[:len(possible_counts)]

                    weights_sum = sum(weights)
                    if weights_sum > 0:
                        weights = [w / weights_sum for w in weights]

                    select_count = random.choices(possible_counts, weights=weights, k=1)[0]

                selected_options = random.sample(_op_list, select_count) if select_count > 0 else []

                for option in selected_options:
                    answer += option[:1]  # 取首字为答案，例如A或B

                answer = "".join(sorted(answer))
            elif q["type"] == "single":
                answer = random.choice(options.split("\n"))[:1]  # 取首字为答案, 例如A或B
            # 判断题处理
            elif q["type"] == "judgement":
                # answer = self.tiku.jugement_select(_answer)
                answer = "true" if random.choice([True, False]) else "false"
            logger.info(f"随机选择 -> {answer}")
            return answer

        def multi_cut(answer: str):
            """
            将多选题答案字符串按特定字符进行切割, 并返回切割后的答案列表

            参数:
            answer(str): 多选题答案字符串.

            返回:
            list[str]: 切割后的答案列表,如果无法切割, 则返回默认的选项列表None

            注意:
            如果无法从网页中提取题目信息,将记录警告日志并返回None
            """
            # cut_char = [',','，','|','\n','\r','\t','#','*','-','_','+','@','~','/','\\','.','&',' ']    # 多选答案切割符
            # ',' 在常规被正确划分的, 选项中出现, 导致 multi_cut 无法正确划分选项 #391
            # IndexError: Cannot choose from an empty sequence #391
            # 同时为了避免没有考虑到的 case, 应该先按照 '\n' 匹配, 匹配不到再按照其他字符匹配
            cut_char = [
                "\n",
                ",",
                "，",
                "|",
                "\r",
                "\t",
                "#",
                "*",
                "-",
                "_",
                "+",
                "@",
                "~",
                "/",
                "\\",
                ".",
                "&",
                " ",
                "、",
            ]  # 多选答案切割符
            res = cut(answer)
            if res is None:
                logger.warning(
                    f"未能从网页中提取题目信息, 以下为相关信息：\n\t{answer}\n\n{_ORIGIN_HTML_CONTENT}\n"
                )  # 尝试输出网页内容和选项信息
                logger.warning("未能正确提取题目选项信息! 请反馈并提供以上信息")
                return None
            else:
                return res

        def clean_res(res):
            cleaned_res = []
            if isinstance(res, str):
                res = [res]
            for c in res:
                # 仅在字符串长度大于1时才尝试去除开头的字母编号，防止误删单个字母答案
                cleaned = re.sub(r'^[A-Za-z]|[.,!?;:，。！？；：]', '', c) if len(c) > 1 else c
                cleaned_res.append(cleaned.strip())

            return cleaned_res

        def is_subsequence(a, o):
            iter_o = iter(o)
            return all(c in iter_o for c in a)

        # FIXME: Use tenacity for retrying
        def with_retry(max_retries=3, delay=1):
            def decorator(func):
                def wrapper(*args, **kwargs):
                    retries = 0
                    while retries < max_retries:
                        try:
                            _resp = func(*args, **kwargs)

                            # 未创建完成该测验则不进行答题，目前遇到的情况是未创建完成等同于没题目
                            if '教师未创建完成该测验' in _resp.text:
                                raise PermissionError("教师未创建完成该测验")

                            questions = decode_questions_info(_resp.text)

                            if _resp.status_code == 200 and questions.get("questions"):
                                return (_resp, questions)

                            logger.warning(
                                f"无效响应 (Code: {getattr(_resp, 'status_code', 'Unknown')}), 重试中... ({retries + 1}/{max_retries})")

                        except requests.exceptions.RequestException as e:
                            logger.warning(f"请求失败: {str(e)[:50]}, 重试中... ({retries + 1}/{max_retries})")
                        retries += 1
                        time.sleep(delay * (2 ** retries))
                    raise MaxRetryExceeded(f"超过最大重试次数 ({max_retries})")

                return wrapper

            return decorator

        # 学习通这里根据参数差异能重定向至两个不同接口, 需要定向至https://mooc1.chaoxing.com/mooc-ans/workHandle/handle
        _session = SessionManager.get_session()

        _url = "https://mooc1.chaoxing.com/mooc-ans/api/work"

        @with_retry(max_retries=3, delay=1)
        def fetch_response():
            return _session.get(
                _url,
                params={
                    "api": "1",
                    "workId": _job["jobid"].replace("work-", ""),
                    "jobid": _job["jobid"],
                    "originJobId": _job["jobid"],
                    "needRedirect": "true",
                    "skipHeader": "true",
                    "knowledgeid": str(_job_info["knowledgeid"]),
                    "ktoken": _job_info["ktoken"],
                    "cpi": _job_info["cpi"],
                    "ut": "s",
                    "clazzId": _course["clazzId"],
                    "type": "",
                    "enc": _job["enc"],
                    "mooc2": "1",
                    "courseid": _course["courseId"],
                }
            )

        final_resp = {}
        questions = {}

        try:
            final_resp, questions = fetch_response()
        except Exception as e:
            logger.error(f"请求失败: {e}")
            return StudyResult.ERROR

        _ORIGIN_HTML_CONTENT = final_resp.text  # 用于配合输出网页源码, 帮助修复#391错误

        # 搜题
        total_questions = len(questions["questions"])
        found_answers = 0
        for q in questions["questions"]:
            logger.debug(f"当前题目信息 -> {q}")
            # 添加搜题延迟 #428 - 默认0s延迟
            query_delay = self.kwargs.get("query_delay", 0)
            time.sleep(query_delay)
            res = self.tiku.query(q)
            answer = ""
            if not res:
                # 随机答题
                answer = random_answer(q["options"])
                q[f'answerSource{q["id"]}'] = "random"
            else:
                # 根据响应结果选择答案
                if q["type"] == "multiple":
                    # 多选处理
                    options_list = multi_cut(q["options"])
                    res_list = multi_cut(res)
                    if res_list is not None and options_list is not None:
                        for _a in clean_res(res_list):
                            for o in options_list:
                                if (
                                        is_subsequence(_a, o)  # 去掉各种符号和前面ABCD的答案应当是选项的子序列
                                ):
                                    answer += o[:1]
                                    break # 找到匹配项后立即停止，防止重复添加
                        # 对答案进行排序, 否则会提交失败
                        answer = "".join(sorted(answer))
                    # else 如果分割失败那么就直接到下面去随机选
                elif q["type"] == "single":
                    # 单选也进行切割，主要是防止返回的答案有异常字符
                    options_list = multi_cut(q["options"])
                    if options_list is not None:
                        t_res = clean_res(res)
                        for o in options_list:
                            if is_subsequence(t_res[0], o):
                                answer = o[:1]
                                break
                elif q["type"] == "judgement":
                    answer = "true" if self.tiku.judgement_select(res) else "false"
                elif q["type"] == "completion":
                    if isinstance(res, list):
                        answer = "".join(res)
                    elif isinstance(res, str):
                        answer = res
                else:
                    # 其他类型直接使用答案 （目前仅知有简答题，待补充处理）
                    answer = res

                if not answer:  # 检查 answer 是否为空
                    logger.warning(f"找到答案但答案未能匹配 -> {res}\t随机选择答案")
                    answer = random_answer(q["options"])  # 如果为空，则随机选择答案
                    q[f'answerSource{q["id"]}'] = "random"
                else:
                    logger.info(f"成功获取到答案：{answer}")
                    q[f'answerSource{q["id"]}'] = "cover"
                    found_answers += 1
            # 填充答案
            q["answerField"][f'answer{q["id"]}'] = answer
            logger.info(f'{q["title"]} 填写答案为 {answer}')
        cover_rate = (found_answers / total_questions) * 100
        logger.info(f"章节检测题库覆盖率： {cover_rate:.0f}%")
        # 提交模式  现在与题库绑定,留空直接提交, 1保存但不提交
        if self.tiku.get_submit_params() == "1":
            questions["pyFlag"] = "1"
        elif cover_rate >= self.tiku.COVER_RATE * 100 or self.rollback_times >= 1:
            questions["pyFlag"] = ""
        else:
            questions["pyFlag"] = "1"
            logger.info(f"章节检测题库覆盖率低于{self.tiku.COVER_RATE * 100:.0f}%，不予提交")
        # 组建提交表单
        if questions["pyFlag"] == "1":
            for q in questions["questions"]:
                questions.update(
                    {
                        f'answer{q["id"]}':
                            q["answerField"][f'answer{q["id"]}'] if q[f'answerSource{q["id"]}'] == "cover" else '',
                        f'answertype{q["id"]}': q["answerField"][f'answertype{q["id"]}'],
                    }
                )
        else:
            for q in questions["questions"]:
                questions.update(
                    {
                        f'answer{q["id"]}': q["answerField"][f'answer{q["id"]}'],
                        f'answertype{q["id"]}': q["answerField"][f'answertype{q["id"]}'],
                    }
                )

        del questions["questions"]

        res = _session.post(
            "https://mooc1.chaoxing.com/mooc-ans/work/addStudentWorkNew",
            data=questions,
            headers={
                "Host": "mooc1.chaoxing.com",
                "sec-ch-ua-platform": '"Windows"',
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "sec-ch-ua": '"Microsoft Edge";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "sec-ch-ua-mobile": "?0",
                "Origin": "https://mooc1.chaoxing.com",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                # "Referer": "https://mooc1.chaoxing.com/mooc-ans/work/doHomeWorkNew?courseId=246831735&workAnswerId=52680423&workId=37778125&api=1&knowledgeid=913820156&classId=107515845&oldWorkId=07647c38d8de4c648a9277c5bed7075a&jobid=work-07647c38d8de4c648a9277c5bed7075a&type=&isphone=false&submit=false&enc=1d826aab06d44a1198fc983ed3d243b1&cpi=338350298&mooc2=1&skipHeader=true&originJobId=work-07647c38d8de4c648a9277c5bed7075a",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,ja;q=0.5",
            },
        )
        if res.status_code == 200:
            res_json = res.json()
            if res_json["status"]:
                logger.info(f'{"提交" if questions["pyFlag"] == "" else "保存"}答题成功 -> {res_json["msg"]}')
            else:
                logger.error(f'{"提交" if questions["pyFlag"] == "" else "保存"}答题失败 -> {res_json["msg"]}')
                return StudyResult.ERROR
        else:
            logger.error(f'{"提交" if questions["pyFlag"] == "" else "保存"}答题失败 -> {res.text}')
            return StudyResult.ERROR
        return StudyResult.SUCCESS

    def study_read(self, _course, _job, _job_info) -> StudyResult:
        """
        阅读任务学习, 仅完成任务点, 并不增长时长
        """
        _session = SessionManager.get_session()
        _resp = _session.get(
            url="https://mooc1.chaoxing.com/ananas/job/readv2",
            params={
                "jobid": _job["jobid"],
                "knowledgeid": _job_info["knowledgeid"],
                "jtoken": _job["jtoken"],
                "courseid": _course["courseId"],
                "clazzid": _course["clazzId"],
            },
        )
        if _resp.status_code != 200:
            logger.error(f"阅读任务学习失败 -> [{_resp.status_code}]{_resp.text}")
            return StudyResult.ERROR
        else:
            _resp_json = _resp.json()
            logger.info(f"阅读任务学习 -> {_resp_json['msg']}")
            return StudyResult.SUCCESS

    def study_emptypage(self, _course, point):
        _session = SessionManager.get_session()
        # &cpi=0&verificationcode=&mooc2=1&microTopicId=0&editorPreview=0
        _resp = _session.get(
            url="https://mooc1.chaoxing.com/mooc-ans/mycourse/studentstudyAjax",
            params={
                "courseId": _course["courseId"],
                "clazzid": _course["clazzId"],
                "chapterId": point["id"],
                "cpi": _course["cpi"],
                "verificationcode": "",
                "mooc2": 1,
                "microTopicId": 0,
                "editorPreview": 0,
            },
        )
        if _resp.status_code != 200:
            logger.error(f"空页面任务失败 -> [{_resp.status_code}]{point['title']}")
            return StudyResult.ERROR
        else:
            logger.info(f"空页面任务完成 -> {point['title']}")
            return StudyResult.SUCCESS
