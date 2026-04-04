import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from pipeline import callbacks


class CallbackRefinementTests(unittest.TestCase):
    def test_refine_callback_verdict_suppresses_public_service_and_policy_noise(self) -> None:
        manifest_info = {
            "package_name": "com.heavysword.chuanshu",
            "launcher_activity": "com.xianan.qxda.im.ui.main.SplashActivity",
            "application_name": "com.heavysword.chuanshu.AndroidApp",
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        selected = {
            "endpoints": {
                "urls": [
                    "https://web.chuanshuim.tech/api/push",
                    "https://apps.apple.com/app/id6450910365",
                    "https://chuanshu.tech/about/chuanshu-privacy.html",
                    "https://chuanshu.tech/about/chuanshu-third-party-info-sharing.html",
                    "https://xxxx-oss.com/app/chuanshu-1.7.6.dmg",
                    "https://data-drcn.push.dbankcloud.com",
                    "https://chuanshu-app-down.oss-cn-shenzhen.aliyuncs.com/file/chuanshuim_v1.14.18_prods.exe",
                ],
                "domains": [
                    "web.chuanshuim.tech",
                    "mgr.chuanshuim.tech",
                    "chuanshu.tech",
                    "apps.apple.com",
                    "grs.dbankcloud.cn",
                    "grs.dbankcloud.com",
                    "xxxx-oss.com",
                    "chuanshu-app-down.oss-cn-shenzhen.aliyuncs.com",
                ],
                "ips": [],
                "emails": [],
            },
            "clues": [
                {"source": "assets/client_global_config.json", "value": "\"ROOT\": \"https://data-drcn.push.dbankcloud.com\""},
                {"source": "assets/client_global_config.json", "value": "\"api\": \"https://web.chuanshuim.tech/api/push\""},
            ],
        }

        refined = callbacks.refine_callback_verdict(manifest_info, selected)

        self.assertIn("https://web.chuanshuim.tech/api/push", refined["endpoints"]["urls"])
        self.assertNotIn("https://apps.apple.com/app/id6450910365", refined["endpoints"]["urls"])
        self.assertNotIn("https://chuanshu.tech/about/chuanshu-privacy.html", refined["endpoints"]["urls"])
        self.assertNotIn("https://chuanshu.tech/about/chuanshu-third-party-info-sharing.html", refined["endpoints"]["urls"])
        self.assertNotIn("https://data-drcn.push.dbankcloud.com", refined["endpoints"]["urls"])
        self.assertNotIn("https://xxxx-oss.com/app/chuanshu-1.7.6.dmg", refined["endpoints"]["urls"])
        self.assertNotIn("https://chuanshu-app-down.oss-cn-shenzhen.aliyuncs.com/file/chuanshuim_v1.14.18_prods.exe", refined["endpoints"]["urls"])
        self.assertIn("web.chuanshuim.tech", refined["endpoints"]["domains"])
        self.assertIn("mgr.chuanshuim.tech", refined["endpoints"]["domains"])
        self.assertIn("chuanshu.tech", refined["endpoints"]["domains"])
        self.assertNotIn("apps.apple.com", refined["endpoints"]["domains"])
        self.assertNotIn("grs.dbankcloud.cn", refined["endpoints"]["domains"])
        self.assertNotIn("grs.dbankcloud.com", refined["endpoints"]["domains"])
        self.assertNotIn("xxxx-oss.com", refined["endpoints"]["domains"])
        self.assertEqual([item["value"] for item in refined["clues"]], ["\"api\": \"https://web.chuanshuim.tech/api/push\""])
        self.assertGreaterEqual(refined["suppressed_count"], 7)


if __name__ == "__main__":
    unittest.main()
