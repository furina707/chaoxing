# -*- coding: utf-8 -*-
"""强制刷音视频时长模式 (force_video_time) 的回归测试。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.decode import _process_attachment_cards  # noqa: E402
from api.base import Chaoxing  # noqa: E402


class ForceVideoTimeDecodeTest(unittest.TestCase):
    def _sample_cards(self):
        return [
            # 已完成的视频任务
            {
                "type": "video", "isPassed": True, "job": True,
                "jobid": "job-video-passed", "otherInfo": "nodeId_1-cpi_2",
                "playTime": 120000, "attDuration": 300,
                "mid": "mid-1", "objectId": "obj-video-1",
                "property": {"name": "passed_video.mp4", "rt": ""},
            },
            # 已完成且 job=None 的章节视频
            {
                "type": "video", "isPassed": True, "job": None,
                "otherInfo": "nodeId_1-cpi_2",
                "mid": "mid-2", "objectId": "obj-video-2",
                "property": {"name": "nontask_video.mp4"},
            },
            # 已完成的测验（两种模式都应跳过）
            {
                "type": "workid", "isPassed": True, "job": True,
                "otherInfo": "nodeId_1-cpi_2", "enc": "enc-1",
                "property": {"workid": "work-1", "jobid": "job-work-1"},
            },
        ]

    def test_default_skips_passed(self):
        self.assertEqual(len(_process_attachment_cards(self._sample_cards())), 0)

    def test_force_video_time_alone_still_skips_passed(self):
        """仅开启 -fvt 时，已完成的音视频仍应被跳过（不重刷）。"""
        jobs = _process_attachment_cards(self._sample_cards(), replay_finished_video=False)
        self.assertEqual(len(jobs), 0)

    def test_replay_keeps_audio_video_only(self):
        """显式开启重刷时，才保留已完成的音视频任务。"""
        jobs = _process_attachment_cards(self._sample_cards(), replay_finished_video=True)
        self.assertEqual(len(jobs), 2)
        self.assertTrue(all(j["type"] == "video" for j in jobs))


class ForceVideoTimeConfigTest(unittest.TestCase):
    def test_default_off(self):
        self.assertFalse(Chaoxing(force_video_time=False).force_video_time)

    def test_enabled(self):
        self.assertTrue(Chaoxing(force_video_time=True).force_video_time)

    def test_replay_default_off(self):
        """重刷已完成音视频默认关闭。"""
        self.assertFalse(Chaoxing(force_video_time=True).replay_finished_video)

    def test_replay_enabled(self):
        self.assertTrue(Chaoxing(replay_finished_video=True).replay_finished_video)

    def test_wait_time_range(self):
        c = Chaoxing(force_video_time=True)
        for _ in range(20):
            self.assertTrue(30 <= c._get_wait_time() <= 58)


if __name__ == "__main__":
    unittest.main()
