# -*- coding: utf-8 -*-
"""用真实 Edge 跑一遍站点：搜索 → 选集 → 播放，检查 video 元素真实状态并截图。"""
import json
import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8000"
TOK = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".token")).read().strip()
OUT = os.path.dirname(os.path.abspath(__file__))
logs = []


def main():
    with sync_playwright() as p:
        br = p.chromium.launch(channel="msedge", headless=True,
                               args=["--autoplay-policy=no-user-gesture-required",
                                     "--no-sandbox", "--disable-dev-shm-usage"])
        ctx = br.new_context(viewport={"width": 1440, "height": 900},
                             ignore_https_errors=True)
        pg = ctx.new_page()
        pg.on("console", lambda m: logs.append(f"[{m.type}] {m.text[:200]}"))
        pg.on("pageerror", lambda e: logs.append(f"[pageerror] {str(e)[:200]}"))

        print("① 打开站点（带令牌）")
        pg.goto(f"{BASE}/?k={TOK}", wait_until="domcontentloaded", timeout=30000)
        pg.wait_for_timeout(1500)
        print("   标题:", pg.title())

        print("\n② 搜索「凡人修仙传」")
        pg.fill("#kw", "凡人修仙传")
        pg.click("button:has-text('搜索')")
        pg.wait_for_selector(".card", timeout=30000)
        n = pg.locator(".card").count()
        first = pg.locator(".card .t").first.inner_text()
        print(f"   结果 {n} 条，首条 = {first}")

        print("\n③ 打开详情 + 选集")
        pg.locator(".card").first.click()
        pg.wait_for_selector(".ep", timeout=30000)
        vtitle = pg.locator("#vtitle").inner_text()
        eps = pg.locator(".ep").count()
        print(f"   {vtitle}  剧集 {eps} 个")

        print("\n④ 点第01集（自动选台）")
        pg.locator(".ep").first.click()
        pg.wait_for_timeout(12000)

        info = pg.evaluate("""() => {
          const v = document.querySelector('#video');
          const act = document.querySelector('#vquality .pl.on');
          const s = v.currentSrc || v.src || '';
          return {
            quality: act ? act.textContent.trim() : null,
            status: document.querySelector('#now').textContent.trim(),
            currentSrc: s.slice(0, 110),
            readyState: v.readyState, currentTime: +v.currentTime.toFixed(2),
            duration: isFinite(v.duration) ? +v.duration.toFixed(1) : null,
            videoWidth: v.videoWidth, videoHeight: v.videoHeight,
            paused: v.paused, error: v.error ? (v.error.code + '/' + v.error.message) : null,
            buffered: v.buffered.length ? +v.buffered.end(v.buffered.length-1).toFixed(2) : 0
          };
        }""")
        print("   自动选中档位 :", info["quality"])
        print("   状态栏       :", info["status"])
        print(f"   分辨率       : {info['videoWidth']}x{info['videoHeight']}")
        print(f"   readyState   : {info['readyState']}  已缓冲 {info['buffered']}s")
        print(f"   播放进度     : {info['currentTime']}s / {info['duration']}s  paused={info['paused']}")
        print(f"   currentSrc   : {info['currentSrc']}")
        if info["error"]:
            print("   ❌ video.error:", info["error"])

        pg.screenshot(path=os.path.join(OUT, "shots_browser_ep1.png"), full_page=False)
        print("\n   截图 → shots_browser_ep1.png")

        print("\n⑤ 手动点 4K 档试试")
        btns = pg.locator("#vquality .pl")
        if btns.count() > 1:
            btns.nth(0).click()
            pg.wait_for_timeout(10000)
            info2 = pg.evaluate("""() => {
              const v = document.querySelector('#video');
              const act = document.querySelector('#vquality .pl.on');
              return {quality: act?act.textContent.trim():null,
                      status: document.querySelector('#now').textContent.trim(),
                      w:v.videoWidth,h:v.videoHeight,readyState:v.readyState,
                      t:+v.currentTime.toFixed(2), error: v.error?v.error.code:null};
            }""")
            print("   选中档位:", info2["quality"])
            print("   状态栏  :", info2["status"])
            print(f"   分辨率  : {info2['w']}x{info2['h']}  readyState={info2['readyState']} t={info2['t']}")
            pg.screenshot(path=os.path.join(OUT, "shots_browser_4k.png"))
            print("   截图 → shots_browser_4k.png")

        print("\n⑥ 控制台日志")
        for l in logs[-15:]:
            print("   ", l)
        br.close()


if __name__ == "__main__":
    main()
