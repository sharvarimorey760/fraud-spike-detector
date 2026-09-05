"""
Fraud-Spike Detector — AI Risk Command Center (3D Cyber SOC Edition)
Built for Razorpay Buildathon — Enterprise Multi-Agent Threat Defense.

Run:
    streamlit run app.py
"""

import glob
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
import html as _html

import pandas as pd
import streamlit as st


# ============================================================
# PROJECT PATHS & SAFE IMPORTS
# ============================================================

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(CURRENT_DIR, "data")):
    BASE_DIR = CURRENT_DIR
elif os.path.exists(os.path.join(os.path.dirname(CURRENT_DIR), "data")):
    BASE_DIR = os.path.dirname(CURRENT_DIR)
else:
    BASE_DIR = CURRENT_DIR

sys.path.append(os.path.join(BASE_DIR, "agent"))
sys.path.append(BASE_DIR)

from env_loader import load_dotenv  # noqa: E402

# Load GEMINI_API_KEY (and any other secrets) from the project's .env
# file, if present. Real environment variables are never overridden.
load_dotenv(os.path.join(BASE_DIR, ".env"))

try:
    from audit_log.logger import read_recent_logs, get_pending_review, mark_reviewed
except ImportError:
    def read_recent_logs(limit=100): return []
    def get_pending_review(limit=100): return []
    def mark_reviewed(tid, note=""): pass

try:
    import agent_loop as agent_loop_module
    from tools import load_dataset as tools_load_dataset
except ImportError:
    agent_loop_module = None
    tools_load_dataset = None

DATA_PATH = os.path.join(BASE_DIR, "data", "transactions.csv")
FLAGGED_PATH = os.path.join(BASE_DIR, "detection", "flagged_events.csv")
REVIEW_ACTIONS_PATH = os.path.join(BASE_DIR, "audit_log", "review_actions.jsonl")


# ============================================================
# STREAMLIT PAGE SETUP
# ============================================================

st.set_page_config(
    page_title="Fraud Command Center — Razorpay SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# COMPATIBILITY HELPERS (ZERO WARNINGS)
# ============================================================

def render_html(html_str: str):
    """Strips leading whitespace so CommonMark never creates code blocks."""
    cleaned = re.sub(r"^[ \t]+", "", html_str, flags=re.MULTILINE)
    st.markdown(cleaned, unsafe_allow_html=True)


def embed_iframe(html_code: str, height: int = 380):
    """Component iframe embed (kept as components.html for broad
    Streamlit-version compatibility — st.iframe with raw HTML source
    is not available on all versions)."""
    import streamlit.components.v1 as components
    components.html(html_code, height=height)


_VOICE_MIC_TEMPLATE = """
<div id="mic-wrap" style="display:flex;flex-direction:column;align-items:center;gap:4px;height:100%;padding-top:14px;">
  <button id="mic-btn" title="Search by voice" type="button" style="
      width:40px;height:40px;border-radius:50%;flex-shrink:0;
      background:#0B131E;border:1px solid #162436;color:#00D9FF;
      font-size:17px;cursor:pointer;display:flex;align-items:center;justify-content:center;
      transition:all .15s ease;">
        <svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" style="display:block;pointer-events:none;">
          <path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3zm5.91-3c-.49 0-.9.36-.98.85C16.52 14.2 14.47 16 12 16s-4.52-1.8-4.93-4.15c-.08-.49-.49-.85-.98-.85-.61 0-1.09.54-1 1.14.49 3 2.89 5.35 5.91 5.78V20c0 .55.45 1 1 1s1-.45 1-1v-2.08c3.02-.43 5.42-2.78 5.91-5.78.1-.6-.39-1.14-1-1.14z"/>
        </svg></button>
  <span id="mic-status" style="font-size:11px;color:#64748B;font-family:Inter,sans-serif;"></span>
</div>
<script>
(function() {
  const btn = document.getElementById('mic-btn');
  const status = document.getElementById('mic-status');
  const targetLabel = "__TARGET_LABEL__";
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

  function setStatus(text, color) {
    status.textContent = text;
    status.style.color = color || '#FACC15';
    btn.title = text;
  }

  if (!SpeechRecognition) {
    setStatus('Voice fill needs Chrome or Edge', '#FF4D67');
    btn.disabled = true;
    btn.style.opacity = 0.4;
    return;
  }

  const recognition = new SpeechRecognition();
  recognition.lang = 'en-IN';
  recognition.continuous = false;
  recognition.interimResults = false;

  let listening = false;

  function findTargetInput() {
    const parentDoc = window.parent.document;
    const labels = Array.from(parentDoc.querySelectorAll('label'));
    const match = labels.find(l => l.textContent.trim() === targetLabel);
    if (!match) return null;
    const container = match.closest('div[data-testid="stTextInput"]') || match.closest('div[class*="stTextInput"]') || match.parentElement.parentElement;
    return container ? container.querySelector('input') : null;
  }

  btn.addEventListener('click', () => {
    if (listening) return;
    setStatus('Tap Allow when the browser asks', '#94A3B8');
    try { recognition.start(); } catch (e) { /* already starting */ }
  });

  recognition.onstart = () => {
    listening = true;
    btn.style.background = '#FF4D67';
    btn.style.borderColor = '#FF4D67';
    setStatus('Listening... speak now', '#00D9FF');
  };

  recognition.onerror = (e) => {
    const friendly = {
      'not-allowed': 'Mic blocked - click the padlock in the address bar and allow Microphone',
      'not-found': 'No microphone found on this device',
      'audio-capture': 'No microphone found on this device',
      'no-speech': 'No speech heard - check the mic and retry',
      'network': 'Speech service busy - retry',
      'service-not-allowed': 'Speech service busy - retry',
      'language-not-supported': 'Language unsupported - retry',
    }[e.error] || ('Mic error: ' + e.error);
    setStatus(friendly, '#FF4D67');
  };

  recognition.onend = () => {
    listening = false;
    btn.style.background = '#0B131E';
    btn.style.borderColor = '#162436';
  };

  recognition.onresult = (event) => {
    const transcript = event.results[0][0].transcript;

    const input = findTargetInput();
    if (!input) {
      setStatus('Could not find the target field', '#FF4D67');
      return;
    }

    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.parent.HTMLInputElement.prototype, 'value'
    ).set;
    nativeSetter.call(input, transcript);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    setStatus('Filled ✓', '#22C55E');

    setTimeout(() => {
      input.dispatchEvent(new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, bubbles: true
      }));
    }, 60);
  };
})();
</script>
"""


def render_voice_search_mic(target_label: str, height: int = 96):
    """Mic button using the browser's built-in Web Speech API
    (webkitSpeechRecognition — Chrome/Edge only, no backend, no API key).

    It reaches into the parent Streamlit document to locate the
    st.text_input by its visible label, writes the transcript into it
    via the native input value setter (so React notices the change),
    then fires a synthetic Enter keypress so Streamlit commits the
    value and reruns — exactly as if the user had typed and pressed
    Enter themselves.
    """
    html_code = _VOICE_MIC_TEMPLATE.replace("__TARGET_LABEL__", target_label)
    embed_iframe(html_code, height=height)


_SPEAK_TEMPLATE = """
<div style="display:flex;flex-direction:column;align-items:flex-start;gap:4px;">
  <button id="speak-btn" title="Read aloud" type="button" style="
      display:inline-flex;align-items:center;gap:7px;padding:7px 14px;
      border-radius:8px;flex-shrink:0;cursor:pointer;
      background:#0B131E;border:1px solid #162436;color:#00D9FF;
      font-size:13px;font-family:Inter,sans-serif;font-weight:500;
      transition:all .15s ease;">
    <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" style="display:block;pointer-events:none;">
      <path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/>
    </svg>
    <span id="speak-label">Read aloud</span>
  </button>
  <span id="speak-status" style="font-size:11px;color:#64748B;font-family:Inter,sans-serif;"></span>
</div>
<script>
(function() {
  const btn = document.getElementById('speak-btn');
  const label = document.getElementById('speak-label');
  const status = document.getElementById('speak-status');
  const text = __SPEAK_TEXT__;
  let speaking = false;

  function stop() {
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
    speaking = false;
    btn.style.background = '#0B131E';
    btn.style.borderColor = '#162436';
    label.textContent = 'Read aloud';
    status.textContent = '';
  }

  if (!('speechSynthesis' in window)) {
    btn.disabled = true;
    btn.style.opacity = 0.4;
    status.textContent = 'Speech synthesis not supported in this browser';
    return;
  }

  btn.addEventListener('click', () => {
    if (speaking) { stop(); return; }
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = 'en-IN';
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    utterance.onstart = () => {
      speaking = true;
      btn.style.background = '#FF4D67';
      btn.style.borderColor = '#FF4D67';
      label.textContent = 'Stop';
      status.textContent = 'Speaking...';
    };
    utterance.onend = stop;
    utterance.onerror = stop;
    window.speechSynthesis.speak(utterance);
  });
})();
</script>
"""


def render_speak_button(text: str, height: int = 74):
    """Read-aloud button using the browser's built-in speechSynthesis
    (Chrome/Edge — no backend, no API key, nothing sent to a server).

    The text is JSON-embedded so quotes/newlines in decision summaries
    can never break out of the script block.
    """
    payload = json.dumps(text, ensure_ascii=False)
    html_code = _SPEAK_TEMPLATE.replace("__SPEAK_TEXT__", payload)
    embed_iframe(html_code, height=height)


# ============================================================
# 3D CYBER GLASSMORPHISM STYLESHEET
# ============================================================

render_html("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
  --bg: #070B12;
  --card-bg: #0B131E;
  --card-border: #162436;
  --cyan: #00D9FF;
  --blue: #3B82F6;
  --red: #FF4D67;
  --orange: #FF9F43;
  --yellow: #FACC15;
  --green: #22C55E;
  --purple: #A855F7;
}

html, body, [class*="css"] {
  font-family: 'Inter', -apple-system, sans-serif;
}

.stApp {
  background: radial-gradient(circle at 50% 0%, rgba(0, 217, 255, 0.04), transparent 40%),
              radial-gradient(circle at 85% 60%, rgba(168, 85, 247, 0.03), transparent 30%),
              #070B12 !important;
  color: #E2E8F0 !important;
}

.block-container {
  max-width: 1580px !important;
  padding: 0.6rem 1.6rem 2.5rem !important;
}

section[data-testid="stSidebar"] {
  background: #05080E !important;
  border-right: 1px solid #142030 !important;
  width: 255px !important;
}

header[data-testid="stHeader"] {
  background: transparent !important;
}

.side-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 4px 18px;
  border-bottom: 1px solid #142030;
  margin-bottom: 18px;
}
.side-brand-icon {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(0,217,255,0.25), rgba(59,130,246,0.1));
  border: 1px solid #00D9FF;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #00D9FF;
  font-size: 19px;
  box-shadow: 0 0 18px rgba(0,217,255,0.3);
}
.side-brand-title {
  font-size: 0.88rem;
  font-weight: 800;
  color: #F8FAFC;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.side-brand-sub {
  font-size: 0.65rem;
  color: #00D9FF;
  font-weight: 600;
}

.status-box {
  background: #080D15;
  border: 1px solid #142233;
  border-radius: 10px;
  padding: 12px 14px;
  margin-top: 24px;
}
.status-title {
  font-size: 0.68rem;
  font-weight: 700;
  color: #94A3B8;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}
.status-online {
  display: flex;
  align-items: center;
  gap: 6px;
  color: #22C55E;
  font-size: 0.72rem;
  font-weight: 600;
  margin-bottom: 10px;
}
.status-online span {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #22C55E;
  box-shadow: 0 0 8px #22C55E;
}
.status-subtext {
  font-size: 0.65rem;
  color: #64748B;
  margin-bottom: 12px;
}
.status-list {
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.status-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.68rem;
  color: #94A3B8;
}
.status-row b {
  display: flex;
  align-items: center;
  gap: 5px;
  color: #22C55E;
  font-weight: 500;
  font-size: 0.65rem;
}
.status-row b i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #22C55E;
  display: inline-block;
}

.user-profile-pill {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  background: #080D15;
  border: 1px solid #142233;
  border-radius: 10px;
  margin-top: 18px;
}
.avatar {
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: #1E293B;
  border: 1px solid #334155;
  color: #F8FAFC;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.75rem;
  font-weight: 700;
}
.user-info { flex: 1; }
.user-name { font-size: 0.74rem; font-weight: 600; color: #F8FAFC; }
.user-role { font-size: 0.62rem; color: #64748B; }

.top-nav {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0 14px;
}
.top-heading h1 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 800;
  color: #F8FAFC;
  letter-spacing: -0.01em;
}
.top-heading p {
  margin: 2px 0 0;
  font-size: 0.76rem;
  color: #64748B;
}

.top-badge-area {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}
.system-op-badge {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 5px 13px;
  border-radius: 999px;
  background: rgba(34, 197, 94, 0.08);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22C55E;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  box-shadow: 0 0 10px rgba(34, 197, 94, 0.15);
}
.system-op-badge span {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #22C55E;
  box-shadow: 0 0 8px #22C55E;
}
.updated-time {
  font-size: 0.66rem;
  color: #64748B;
  font-family: 'JetBrains Mono', monospace;
}

.kpi-row {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 12px;
  margin-bottom: 6px;
}
.kpi-card-3d {
  background: linear-gradient(135deg, rgba(13, 22, 34, 0.8), rgba(8, 13, 21, 0.95));
  border: 1px solid #162538;
  border-radius: 14px 14px 0 0;
  padding: 16px 17px 8px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  min-height: 110px;
  backdrop-filter: blur(14px);
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 10px 28px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.04);
}

.glow-cyan { border-color: rgba(0, 217, 255, 0.5) !important; box-shadow: 0 0 25px rgba(0, 217, 255, 0.2), inset 0 0 12px rgba(0, 217, 255, 0.06) !important; }
.glow-red { border-color: rgba(255, 77, 103, 0.5) !important; box-shadow: 0 0 25px rgba(255, 77, 103, 0.2), inset 0 0 12px rgba(255, 77, 103, 0.06) !important; }
.glow-orange { border-color: rgba(255, 159, 67, 0.5) !important; box-shadow: 0 0 25px rgba(255, 159, 67, 0.2), inset 0 0 12px rgba(255, 159, 67, 0.06) !important; }
.glow-crimson { border-color: rgba(239, 68, 68, 0.5) !important; box-shadow: 0 0 25px rgba(239, 68, 68, 0.2), inset 0 0 12px rgba(239, 68, 68, 0.06) !important; }
.glow-purple { border-color: rgba(168, 85, 247, 0.5) !important; box-shadow: 0 0 25px rgba(168, 85, 247, 0.2), inset 0 0 12px rgba(168, 85, 247, 0.06) !important; }

.kpi-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}
.kpi-title {
  font-size: 0.65rem;
  font-weight: 700;
  color: #7E92A2;
  letter-spacing: 0.07em;
  text-transform: uppercase;
}
.kpi-icon-wrap {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
}
.kpi-icon-blue { background: rgba(59, 130, 246, 0.15); color: #3B82F6; border: 1px solid rgba(59, 130, 246, 0.3); }
.kpi-icon-red { background: rgba(255, 77, 103, 0.15); color: #FF4D67; border: 1px solid rgba(255, 77, 103, 0.3); }
.kpi-icon-orange { background: rgba(255, 159, 67, 0.15); color: #FF9F43; border: 1px solid rgba(255, 159, 67, 0.3); }
.kpi-icon-crimson { background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); }
.kpi-icon-purple { background: rgba(168, 85, 247, 0.15); color: #A855F7; border: 1px solid rgba(168, 85, 247, 0.3); }

.kpi-num {
  font-family: 'Inter', sans-serif;
  font-size: 1.7rem;
  font-weight: 800;
  color: #F8FAFC;
  margin: 6px 0 2px;
  display: flex;
  align-items: baseline;
  gap: 5px;
}
.kpi-num small {
  font-size: 0.78rem;
  color: #64748B;
  font-weight: 500;
}
.kpi-tag-amber {
  font-size: 0.60rem;
  padding: 2px 7px;
  border-radius: 4px;
  background: rgba(245, 158, 11, 0.18);
  border: 1px solid rgba(245, 158, 11, 0.4);
  color: #F59E0B;
  font-weight: 700;
  display: inline-block;
  margin-left: 6px;
}
.kpi-sub { font-size: 0.68rem; color: #64748B; }
.kpi-delta-green { font-size: 0.68rem; color: #22C55E; font-weight: 700; margin-top: 4px; }
.kpi-delta-red { font-size: 0.68rem; color: #FF4D67; font-weight: 700; margin-top: 4px; }
.kpi-delta-orange { font-size: 0.68rem; color: #FF9F43; font-weight: 700; margin-top: 4px; }

/* Make the drill-down button under each KPI look like it belongs to
   the card above it (rounded bottom corners only, matching border) */
div[data-testid="column"] .stButton > button {
  border-radius: 0 0 14px 14px !important;
  border-top: none !important;
  margin-top: -1px;
  background: rgba(8,13,21,0.9) !important;
  color: #7E92A2 !important;
  font-size: 0.68rem !important;
  font-weight: 600 !important;
  min-height: 30px !important;
  padding: 2px 8px !important;
}
div[data-testid="column"] .stButton > button:hover {
  color: #F8FAFC !important;
  background: rgba(13,22,34,0.95) !important;
}

.c-panel {
  background: linear-gradient(145deg, #0B131E, #070D16);
  border: 1px solid #162436;
  border-radius: 12px;
  padding: 16px 18px;
  height: 100%;
  box-shadow: 0 8px 24px rgba(0,0,0,0.3);
}
.panel-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.panel-head-title {
  font-size: 0.75rem;
  font-weight: 700;
  color: #F1F5F9;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.panel-foot-link {
  display: inline-block;
  font-size: 0.70rem;
  font-weight: 600;
  color: #00D9FF;
  text-decoration: none;
  margin-top: 12px;
  cursor: pointer;
}

.donut-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 6px 0;
}
.donut-svg-wrap {
  position: relative;
  width: 170px;
  height: 170px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.donut-center-text {
  position: absolute;
  text-align: center;
}
.donut-center-val {
  font-size: 1.55rem;
  font-weight: 800;
  color: #F8FAFC;
  font-family: 'Inter', sans-serif;
}
.donut-center-lbl {
  font-size: 0.62rem;
  color: #64748B;
  text-transform: uppercase;
}
.donut-legend {
  width: 100%;
  display: flex;
  flex-direction: column;
  gap: 7px;
  margin-top: 12px;
}
.donut-leg-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.68rem;
  color: #94A3B8;
}
.donut-leg-row span {
  display: flex;
  align-items: center;
  gap: 7px;
}
.donut-leg-row i {
  width: 8px;
  height: 8px;
  border-radius: 2px;
  display: inline-block;
}
.donut-leg-row b {
  color: #F1F5F9;
  font-family: 'JetBrains Mono', monospace;
}

.live-badge {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 0.65rem;
  font-weight: 700;
  color: #22C55E;
}
.live-badge span {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #22C55E;
  box-shadow: 0 0 6px #22C55E;
}
.event-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 9px 10px;
  background: #080E17;
  border: 1px solid #142030;
  border-radius: 8px;
  margin-bottom: 7px;
}
.event-left {
  display: flex;
  align-items: center;
  gap: 10px;
}
.risk-pill-crit {
  padding: 3px 6px;
  border-radius: 4px;
  background: rgba(239, 68, 68, 0.15);
  border: 1px solid rgba(239, 68, 68, 0.35);
  color: #FF4D67;
  font-size: 0.60rem;
  font-weight: 700;
}
.risk-pill-high {
  padding: 3px 6px;
  border-radius: 4px;
  background: rgba(255, 159, 67, 0.15);
  border: 1px solid rgba(255, 159, 67, 0.35);
  color: #FF9F43;
  font-size: 0.60rem;
  font-weight: 700;
}
.risk-pill-med {
  padding: 3px 6px;
  border-radius: 4px;
  background: rgba(250, 204, 21, 0.15);
  border: 1px solid rgba(250, 204, 21, 0.35);
  color: #FACC15;
  font-size: 0.60rem;
  font-weight: 700;
}
.risk-pill-low {
  padding: 3px 6px;
  border-radius: 4px;
  background: rgba(34, 197, 94, 0.15);
  border: 1px solid rgba(34, 197, 94, 0.35);
  color: #22C55E;
  font-size: 0.60rem;
  font-weight: 700;
}
.event-details {
  display: flex;
  flex-direction: column;
}
.event-id {
  font-size: 0.72rem;
  font-weight: 600;
  color: #F1F5F9;
  font-family: 'JetBrains Mono', monospace;
}
.event-msg {
  font-size: 0.62rem;
  color: #64748B;
}
.event-time {
  font-size: 0.65rem;
  color: #475569;
  font-family: 'JetBrains Mono', monospace;
}

.pipe-container {
  background: linear-gradient(135deg, rgba(13, 22, 34, 0.8), rgba(8, 13, 21, 0.95));
  border: 1px solid #162436;
  border-radius: 14px;
  padding: 16px 20px;
  margin-top: 16px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.4);
}
.pipe-title {
  font-size: 0.74rem;
  font-weight: 800;
  color: #F8FAFC;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  margin-bottom: 14px;
}
.pipe-steps {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  overflow-x: auto;
}
.pipe-card {
  flex: 1;
  min-width: 140px;
  height: 60px;
  background: #080E17;
  border: 1px solid #142030;
  border-radius: 10px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 12px;
  transition: all 0.25s ease;
}
.pipe-card.active {
  border-color: #00D9FF;
  background: linear-gradient(135deg, rgba(0, 217, 255, 0.12), #080E17);
  box-shadow: 0 0 20px rgba(0, 217, 255, 0.2);
}
.pipe-icon-box {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  background: #0D1724;
  border: 1px solid #1A293D;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
}
.pipe-card.active .pipe-icon-box {
  background: rgba(0, 217, 255, 0.2);
  border-color: #00D9FF;
  color: #00D9FF;
}
.pipe-text { display: flex; flex-direction: column; }
.pipe-step-num { font-size: 0.58rem; color: #64748B; font-weight: 700; }
.pipe-card.active .pipe-step-num { color: #00D9FF; }
.pipe-step-name { font-size: 0.68rem; font-weight: 700; color: #F1F5F9; line-height: 1.2; }
.pipe-arrow { color: #334155; font-size: 1.1rem; }

.detail-panel {
  background: linear-gradient(145deg, #0D1724, #080E17);
  border: 1px solid #00D9FF;
  box-shadow: 0 0 30px rgba(0,217,255,0.12);
  border-radius: 14px;
  padding: 18px 20px;
  margin: 4px 0 20px;
}
</style>
""")


# ============================================================
# CONFIG (real settings written by the Settings tab, read by the
# real backend scripts — not just cosmetic sliders)
# ============================================================

CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_CONFIG = {
    "model": "gemini-3.5-flash-lite",
    "contamination": 0.10,
    "cooldown_minutes": 15,
    "min_escalate_confidence": 0.85,
}


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                cfg = json.load(f)
            merged = dict(DEFAULT_CONFIG)
            merged.update(cfg)
            return merged
        except (json.JSONDecodeError, OSError):
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


# ============================================================
# DATA SOURCE LOADER — real numbers computed from actual files,
# never hardcoded. If a file is missing, this says so honestly
# instead of silently showing invented numbers.
# ============================================================

@st.cache_data(ttl=30)
def load_telemetry():
    df = pd.DataFrame()
    flagged = pd.DataFrame()
    data_missing = not os.path.exists(DATA_PATH)
    flagged_missing = not os.path.exists(FLAGGED_PATH)

    if os.path.exists(DATA_PATH):
        try:
            df = pd.read_csv(DATA_PATH)
        except Exception:
            data_missing = True

    if os.path.exists(FLAGGED_PATH):
        try:
            flagged = pd.read_csv(FLAGGED_PATH)
        except Exception:
            flagged_missing = True

    total = len(df)
    flagged_count = len(flagged)

    pending_list = get_pending_review(limit=5000)
    pending_count = len(pending_list)

    if not flagged.empty and "risk_score" in flagged.columns:
        avg_risk = round(float(flagged["risk_score"].mean()), 1)
        crit_count = int((flagged["risk_score"] >= 85).sum())
    else:
        avg_risk = None
        crit_count = None

    return {
        "total": total,
        "flagged_count": flagged_count,
        "avg_risk": avg_risk,
        "crit_count": crit_count,
        "pending_count": pending_count,
        "df": df,
        "flagged": flagged,
        "data_missing": data_missing,
        "flagged_missing": flagged_missing,
    }


telemetry = load_telemetry()
total_txns = telemetry["total"]
flagged_txns = telemetry["flagged_count"]
avg_risk_score = telemetry["avg_risk"]
critical_events = telemetry["crit_count"]
pending_review = telemetry["pending_count"]
df_raw = telemetry["df"]
df_flagged = telemetry["flagged"]


def risk_tier_counts(flagged_df: pd.DataFrame) -> dict:
    """Real risk-tier breakdown from the actual flagged dataset."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if flagged_df.empty or "risk_score" not in flagged_df.columns:
        return counts
    scores = flagged_df["risk_score"]
    counts["CRITICAL"] = int((scores >= 85).sum())
    counts["HIGH"] = int(((scores >= 65) & (scores < 85)).sum())
    counts["MEDIUM"] = int(((scores >= 40) & (scores < 65)).sum())
    counts["LOW"] = int((scores < 40).sum())
    return counts


def _discover_csv_files() -> list:
    """Find CSV files already present in the project's data folders."""
    patterns = [
        os.path.join(BASE_DIR, "data", "*.csv"),
        os.path.join(BASE_DIR, "detection", "*.csv"),
        os.path.join(BASE_DIR, "dashboard", "*.csv"),
    ]
    paths = []
    for pattern in patterns:
        paths.extend(glob.glob(pattern))
    return sorted(set(paths))


# ============================================================
# SIDEBAR
# ============================================================

if "kpi_selected" not in st.session_state:
    st.session_state.kpi_selected = None

with st.sidebar:
    render_html("""
    <div class="side-brand">
      <div class="side-brand-icon">🛡️</div>
      <div>
        <div class="side-brand-title">Razorpay SOC</div>
        <div class="side-brand-sub">AI Threat Command</div>
      </div>
    </div>
    """)

    nav_option = st.radio(
        "Navigation",
        [
            "🏠 Dashboard",
            "🚩 Flagged Events",
            "👤 Human Review",
            "📜 Audit Log",
            "🔍 Single Investigation",
            "⚡ Batch Investigation",
            "📊 Analytics",
            "🔔 Alerts",
            "📄 Reports",
            "⚙️ Settings",
        ],
        label_visibility="collapsed",
    )

    render_html("""
    <div class="status-box">
      <div class="status-title">SYSTEM STATUS</div>
      <div class="status-online"><span></span> ONLINE</div>
      <div class="status-subtext">All guards operational</div>
      <div class="status-list">
        <div class="status-row"><span>AI Investigator (Gemini)</span><b><i></i> Active</b></div>
        <div class="status-row"><span>Critic Agent</span><b><i></i> Active</b></div>
        <div class="status-row"><span>Anomaly Detection</span><b><i></i> Active</b></div>
        <div class="status-row"><span>Guardrail Gate</span><b><i></i> Active</b></div>
        <div class="status-row"><span>Audit Trail</span><b><i></i> Active</b></div>
        <div class="status-row"><span>Human-in-the-Loop</span><b><i></i> Active</b></div>
      </div>
    </div>

    <div class="user-profile-pill">
      <div class="avatar">R</div>
      <div class="user-info">
        <div class="user-name">Risk Analyst</div>
        <div class="user-role">SOC Reviewer</div>
      </div>
    </div>
    """)


# ============================================================
# 1. VIEW: DASHBOARD
# ============================================================
if nav_option == "🏠 Dashboard":
    now_time = datetime.now().strftime("%H:%M:%S")
    render_html(f"""
    <div class="top-nav">
      <div class="top-heading">
        <h1>Fraud Command Center</h1>
        <p>AI-powered fraud monitoring, backed by real telemetry — every number below is computed from the current dataset, not simulated.</p>
      </div>
      <div class="top-badge-area">
        <div class="system-op-badge"><span></span> SYSTEM OPERATIONAL</div>
        <div class="updated-time">Last refreshed: {now_time} ↻</div>
      </div>
    </div>
    """)

    if telemetry["data_missing"]:
        st.warning("No transactions.csv found — run data/generate_synthetic_data.py first. Numbers below are 0 until then.")
    if telemetry["flagged_missing"]:
        st.warning("No flagged_events.csv found — run detection/anomaly_scorer.py first. Risk numbers below are unavailable until then.")

    avg_risk_display = f"{avg_risk_score}" if avg_risk_score is not None else "—"
    crit_display = critical_events if critical_events is not None else "—"

    render_html(f"""
    <div class="kpi-row">
      <div class="kpi-card-3d glow-cyan">
        <div class="kpi-header">
          <span class="kpi-title">TOTAL TRANSACTIONS</span>
          <div class="kpi-icon-wrap kpi-icon-blue">🗄️</div>
        </div>
        <div>
          <div class="kpi-num">{total_txns:,}</div>
          <div class="kpi-sub">all ingested telemetry</div>
        </div>
      </div>

      <div class="kpi-card-3d glow-red">
        <div class="kpi-header">
          <span class="kpi-title">FLAGGED TRANSACTIONS</span>
          <div class="kpi-icon-wrap kpi-icon-red">⚠️</div>
        </div>
        <div>
          <div class="kpi-num">{flagged_txns:,}</div>
          <div class="kpi-sub">{(flagged_txns/total_txns*100) if total_txns else 0:.1f}% anomaly rate</div>
        </div>
      </div>

      <div class="kpi-card-3d glow-orange">
        <div class="kpi-header">
          <span class="kpi-title">AVERAGE RISK SCORE</span>
          <div class="kpi-icon-wrap kpi-icon-orange">🛡️</div>
        </div>
        <div>
          <div class="kpi-num">{avg_risk_display} <small>/ 100</small></div>
          <div class="kpi-sub">mean of flagged events</div>
        </div>
      </div>

      <div class="kpi-card-3d glow-crimson">
        <div class="kpi-header">
          <span class="kpi-title">CRITICAL EVENTS</span>
          <div class="kpi-icon-wrap kpi-icon-crimson">💀</div>
        </div>
        <div>
          <div class="kpi-num">{crit_display}</div>
          <div class="kpi-sub">score ≥ 85/100</div>
        </div>
      </div>

      <div class="kpi-card-3d glow-purple">
        <div class="kpi-header">
          <span class="kpi-title">PENDING HUMAN REVIEW</span>
          <div class="kpi-icon-wrap kpi-icon-purple">👤</div>
        </div>
        <div>
          <div class="kpi-num">{pending_review}</div>
          <div class="kpi-sub">awaiting signoff</div>
        </div>
      </div>
    </div>
    """)

    # Clickable drill-down buttons directly under each KPI card
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        if st.button("View transactions ▾", key="kpi_btn_total", use_container_width=True):
            st.session_state.kpi_selected = "total" if st.session_state.kpi_selected != "total" else None
    with k2:
        if st.button("View flagged ▾", key="kpi_btn_flagged", use_container_width=True):
            st.session_state.kpi_selected = "flagged" if st.session_state.kpi_selected != "flagged" else None
    with k3:
        if st.button("View risk breakdown ▾", key="kpi_btn_risk", use_container_width=True):
            st.session_state.kpi_selected = "risk" if st.session_state.kpi_selected != "risk" else None
    with k4:
        if st.button("View critical events ▾", key="kpi_btn_crit", use_container_width=True):
            st.session_state.kpi_selected = "critical" if st.session_state.kpi_selected != "critical" else None
    with k5:
        if st.button("View pending queue ▾", key="kpi_btn_pending", use_container_width=True):
            st.session_state.kpi_selected = "pending" if st.session_state.kpi_selected != "pending" else None

    # --- Detail panel: real content based on which KPI was clicked ---
    sel = st.session_state.kpi_selected
    if sel == "total":
        render_html('<div class="detail-panel"><b>Recent transactions</b></div>')
        if not df_raw.empty:
            st.dataframe(df_raw.tail(15), use_container_width=True, hide_index=True)
        else:
            st.info("No transaction data loaded yet.")

    elif sel == "flagged":
        render_html('<div class="detail-panel"><b>Flagged transactions</b> — surfaced by the anomaly detector</div>')
        if not df_flagged.empty:
            st.dataframe(df_flagged.head(20), use_container_width=True, hide_index=True)
        else:
            st.info("No flagged events loaded yet.")

    elif sel == "risk":
        counts = risk_tier_counts(df_flagged)
        render_html('<div class="detail-panel"><b>Risk tier breakdown</b> — computed from flagged_events.csv</div>')
        rc1, rc2, rc3, rc4 = st.columns(4)
        rc1.metric("🔴 Critical", counts["CRITICAL"])
        rc2.metric("🟠 High", counts["HIGH"])
        rc3.metric("🟡 Medium", counts["MEDIUM"])
        rc4.metric("🟢 Low", counts["LOW"])

    elif sel == "critical":
        render_html('<div class="detail-panel"><b>Critical events</b> — risk_score ≥ 85</div>')
        if not df_flagged.empty and "risk_score" in df_flagged.columns:
            crit_rows = df_flagged[df_flagged["risk_score"] >= 85]
            if not crit_rows.empty:
                st.dataframe(crit_rows, use_container_width=True, hide_index=True)
            else:
                st.success("No critical-risk events in the current dataset.")
        else:
            st.info("No risk-scored data loaded yet.")

    elif sel == "pending":
        render_html('<div class="detail-panel"><b>Pending human review</b> — escalated or held decisions awaiting signoff</div>')
        pending_items = get_pending_review(limit=50)
        if pending_items:
            for item in pending_items:
                dec = item.get("decision", {})
                st.write(
                    f"**{item.get('transaction_id')}** — "
                    f"`{dec.get('recommended_action')}` "
                    f"(confidence {dec.get('confidence')}) — "
                    f"{dec.get('reasoning_summary', '')[:140]}"
                )
        else:
            st.success("Nothing pending — all decisions have been reviewed.")

    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

    # --------------------------------------------------------
    # Risk distribution (real) + live event feed (real, from
    # actual logged agent decisions, not invented transactions)
    # --------------------------------------------------------
    col_donut, col_feed = st.columns([0.95, 1.55])

    with col_donut:
        counts = risk_tier_counts(df_flagged)
        total_for_donut = sum(counts.values()) or 1
        pct = {k: (v / total_for_donut * 100) for k, v in counts.items()}
        # arc lengths for a 116-radius-equivalent circumference (approx, matches viewBox below)
        circumference = 364.4
        crit_len = pct["CRITICAL"] / 100 * circumference
        high_len = pct["HIGH"] / 100 * circumference
        med_len = pct["MEDIUM"] / 100 * circumference
        low_len = pct["LOW"] / 100 * circumference

        render_html(f"""
        <div class="c-panel">
          <div class="panel-head">
            <span class="panel-head-title">RISK DISTRIBUTION</span>
          </div>
          <div class="donut-container">
            <div class="donut-svg-wrap">
              <svg viewBox="0 0 160 160" style="width:150px;height:150px;transform:rotate(-90deg);">
                <circle cx="80" cy="80" r="58" stroke="#121D2C" stroke-width="18" fill="none"/>
                <circle cx="80" cy="80" r="58" stroke="#22C55E" stroke-width="18" stroke-dasharray="{low_len:.1f} {circumference}" stroke-dashoffset="0" fill="none"/>
                <circle cx="80" cy="80" r="58" stroke="#FACC15" stroke-width="18" stroke-dasharray="{med_len:.1f} {circumference}" stroke-dashoffset="-{low_len:.1f}" fill="none"/>
                <circle cx="80" cy="80" r="58" stroke="#FF9F43" stroke-width="18" stroke-dasharray="{high_len:.1f} {circumference}" stroke-dashoffset="-{low_len+med_len:.1f}" fill="none"/>
                <circle cx="80" cy="80" r="58" stroke="#FF4D67" stroke-width="18" stroke-dasharray="{crit_len:.1f} {circumference}" stroke-dashoffset="-{low_len+med_len+high_len:.1f}" fill="none"/>
              </svg>
              <div class="donut-center-text">
                <div class="donut-center-val">{flagged_txns}</div>
                <div class="donut-center-lbl">Total Flagged</div>
              </div>
            </div>
            <div class="donut-legend">
              <div class="donut-leg-row"><span><i style="background:#FF4D67;"></i> CRITICAL</span><b>{counts['CRITICAL']} ({pct['CRITICAL']:.1f}%)</b></div>
              <div class="donut-leg-row"><span><i style="background:#FF9F43;"></i> HIGH</span><b>{counts['HIGH']} ({pct['HIGH']:.1f}%)</b></div>
              <div class="donut-leg-row"><span><i style="background:#FACC15;"></i> MEDIUM</span><b>{counts['MEDIUM']} ({pct['MEDIUM']:.1f}%)</b></div>
              <div class="donut-leg-row"><span><i style="background:#22C55E;"></i> LOW</span><b>{counts['LOW']} ({pct['LOW']:.1f}%)</b></div>
            </div>
          </div>
        </div>
        """)

    with col_feed:
        recent_logs = read_recent_logs(limit=8)
        items_html = ""
        if recent_logs:
            for entry in reversed(recent_logs):
                dec = entry.get("decision", {})
                action = dec.get("recommended_action", "flag_for_review")
                pill_class = {
                    "escalate": "risk-pill-crit",
                    "soft_hold": "risk-pill-high",
                    "flag_for_review": "risk-pill-med",
                    "dismiss": "risk-pill-low",
                }.get(action, "risk-pill-med")
                pill_label = action.replace("_", " ").upper()
                tid = str(entry.get("transaction_id", ""))[:16]
                msg = _html.escape(str(dec.get("reasoning_summary", ""))[:60])
                logged_at = str(entry.get("logged_at", ""))[11:19]
                items_html += f"""
                <div class="event-item">
                  <div class="event-left">
                    <span class="{pill_class}">{pill_label}</span>
                    <div class="event-details">
                      <span class="event-id">{tid}</span>
                      <span class="event-msg">{msg}</span>
                    </div>
                  </div>
                  <span class="event-time">{logged_at}</span>
                </div>
                """
        else:
            items_html = '<div style="color:#64748B;font-size:0.75rem;padding:8px 0;">No agent decisions logged yet — run an investigation to populate this feed.</div>'

        render_html(f"""
        <div class="c-panel">
          <div class="panel-head">
            <span class="panel-head-title">RECENT AGENT DECISIONS</span>
            <div class="live-badge"><span></span> FROM AUDIT LOG</div>
          </div>
          <div style="display:flex;flex-direction:column;gap:5px;">
            {items_html}
          </div>
        </div>
        """)

    # Bottom 7-stage pipeline (labels only — this describes the
    # actual architecture, no fabricated numbers involved)
    render_html("""
    <div class="pipe-container">
      <div class="pipe-title">AI FRAUD DETECTION PIPELINE</div>
      <div class="pipe-steps">
        <div class="pipe-card">
          <div class="pipe-icon-box" style="color:#3B82F6;">🗄️</div>
          <div class="pipe-text"><span class="pipe-step-num">1</span><span class="pipe-step-name">TRANSACTION<br>TELEMETRY</span></div>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-card">
          <div class="pipe-icon-box" style="color:#00D9FF;">🛡️</div>
          <div class="pipe-text"><span class="pipe-step-num">2</span><span class="pipe-step-name">ANOMALY<br>DETECTION</span></div>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-card active">
          <div class="pipe-icon-box">🧠</div>
          <div class="pipe-text"><span class="pipe-step-num">3</span><span class="pipe-step-name">AI<br>INVESTIGATOR</span></div>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-card active">
          <div class="pipe-icon-box">🔍</div>
          <div class="pipe-text"><span class="pipe-step-num">4</span><span class="pipe-step-name">CRITIC<br>AGENT</span></div>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-card">
          <div class="pipe-icon-box" style="color:#22C55E;">🛡️</div>
          <div class="pipe-text"><span class="pipe-step-num">5</span><span class="pipe-step-name">GUARDRAILS</span></div>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-card">
          <div class="pipe-icon-box" style="color:#A855F7;">👤</div>
          <div class="pipe-text"><span class="pipe-step-num">6</span><span class="pipe-step-name">HUMAN<br>REVIEW</span></div>
        </div>
        <span class="pipe-arrow">→</span>
        <div class="pipe-card">
          <div class="pipe-icon-box" style="color:#FF9F43;">📄</div>
          <div class="pipe-text"><span class="pipe-step-num">7</span><span class="pipe-step-name">AUDIT<br>TRAIL</span></div>
        </div>
      </div>
    </div>
    """)


# ============================================================
# 2. VIEW: FLAGGED EVENTS
# ============================================================
elif nav_option == "🚩 Flagged Events":
    st.markdown("## 🚩 Flagged Events Intelligence")
    st.caption("Telemetry records surfaced by the anomaly scorer — real data, no fallback rows.")

    view = df_flagged.copy()

    if view.empty:
        st.warning("No flagged_events.csv found. Run detection/anomaly_scorer.py to generate it.")
    else:
        tier_col = None
        for candidate in ["risk_priority", "risk_level", "tier"]:
            if candidate in view.columns:
                tier_col = candidate
                break
        if not tier_col and "risk_score" in view.columns:
            view["risk_priority"] = view["risk_score"].apply(
                lambda s: "CRITICAL" if s >= 85 else "HIGH" if s >= 65 else "MEDIUM" if s >= 40 else "LOW"
            )
            tier_col = "risk_priority"

        total_records = len(view)

        f1, f2, f3, f4 = st.columns([1.2, 2.0, 0.4, 0.5])
        with f1:
            tier_options = sorted(view[tier_col].astype(str).str.upper().unique()) if tier_col else []
            selected_tiers = st.multiselect("Filter Risk Tier", tier_options, default=tier_options)
        with f2:
            search_label = "Search Merchant, Device, Transaction ID"
            search_query = st.text_input(
                search_label,
                placeholder="Type, press Enter, or tap the mic button...",
            )
        with f3:
            render_voice_search_mic(search_label)
        with f4:
            st.write("")
            st.write("")
            if st.button("Reset", use_container_width=True):
                st.rerun()

        if tier_col and selected_tiers:
            view = view[view[tier_col].astype(str).str.upper().isin([t.upper() for t in selected_tiers])]

        if search_query:
            q = search_query.strip().lower()
            if q:
                mask = view.astype(str).apply(lambda col: col.str.lower().str.contains(q, na=False)).any(axis=1)
                view = view[mask]

        st.markdown(f"**Showing `{len(view)}` of `{total_records}` flagged transactions**")

        if view.empty:
            st.warning("No records match the current filter/search.")
        else:
            preferred_order = ["transaction_id", "merchant_id", "device_id", "transaction_amount", "risk_score", tier_col]
            lead_cols = [c for c in preferred_order if c and c in view.columns]
            rest_cols = [c for c in view.columns if c not in lead_cols]
            st.dataframe(view[lead_cols + rest_cols], use_container_width=True, hide_index=True)


# ============================================================
# 3. VIEW: HUMAN REVIEW
# ============================================================
elif nav_option == "👤 Human Review":
    st.markdown("## 👤 Analyst Human Review Queue")
    st.caption("Decisions held or escalated by the AI & guardrail policies, awaiting sign-off.")

    pending_items = get_pending_review(limit=1000)
    if not pending_items:
        st.success("✅ All flagged decisions have been signed off. Nothing pending.")
    else:
        st.warning(f"⚠️ {len(pending_items)} decision(s) require analyst sign-off.")
        for idx, item in enumerate(pending_items[:100]):
            dec = item.get("decision", {})
            tid = item.get("transaction_id", f"item-{idx}")
            unique = f"{idx}_{item.get('logged_at', '')}"
            with st.expander(f"🔴 {tid} — {dec.get('recommended_action', 'escalate').upper()} (confidence {dec.get('confidence', '?')})"):
                st.write(f"**Merchant:** {item.get('merchant_id')} | **Device:** {item.get('device_id')}")
                st.write(f"**Investigator reasoning:** {dec.get('reasoning_summary', '')}")
                if dec.get("critic_summary"):
                    st.caption(f"🛡️ Critic verdict: {dec.get('critic_summary')}")
                note = st.text_input("Analyst review note", key=f"note_{unique}")
                c1, c2, c3 = st.columns(3)
                with c1:
                    if st.button("✅ Approve", key=f"app_{unique}", use_container_width=True):
                        mark_reviewed(tid, f"approved: {note}")
                        st.rerun()
                with c2:
                    if st.button("⛔ Reject", key=f"rej_{unique}", use_container_width=True):
                        mark_reviewed(tid, f"rejected: {note}")
                        st.rerun()
                with c3:
                    if st.button("↕ Override", key=f"ovr_{unique}", use_container_width=True):
                        mark_reviewed(tid, f"overridden: {note}")
                        st.rerun()


# ============================================================
# 4. VIEW: AUDIT LOG
# ============================================================
elif nav_option == "📜 Audit Log":
    st.markdown("## 📜 Decision Audit Trail")
    st.caption("Every investigator decision, critic evaluation, and guardrail adjustment, in order logged.")

    logs = read_recent_logs(limit=100)
    if logs:
        for entry in reversed(logs):
            dec = entry.get("decision", {})
            with st.expander(f"📋 {entry.get('transaction_id')} — {dec.get('recommended_action', 'flag').upper()} at {entry.get('logged_at')}"):
                st.write(f"**Reasoning:** {dec.get('reasoning_summary')}")
                if dec.get("critic_summary"):
                    st.caption(f"🛡️ **Critic Agent Verdict:** {dec.get('critic_summary')}")
                if dec.get("recommended_remediation"):
                    st.info(f"**Remediation:** {dec.get('recommended_remediation')}")
                st.json(dec)

                # AI voice: read the decision reasoning aloud.
                speak_text = (
                    f"Recommended action: {dec.get('recommended_action', 'flag for review')}. "
                    f"Fraud pattern: {dec.get('fraud_type_guess', 'unknown')}. "
                    f"Confidence: {dec.get('confidence', 0)}. "
                    f"Reasoning: {dec.get('reasoning_summary', 'No reasoning recorded.')}"
                )
                if dec.get("critic_summary"):
                    speak_text += f" Critic verdict: {dec.get('critic_summary')}"
                if dec.get("recommended_remediation"):
                    speak_text += f" Recommended remediation: {dec.get('recommended_remediation')}"
                render_speak_button(speak_text)
    else:
        st.info("No audit logs found yet. Run an investigation to generate entries.")


# ============================================================
# 5. VIEW: SINGLE INVESTIGATION
# ============================================================
elif nav_option == "🔍 Single Investigation":
    st.markdown("## 🔍 Live Multi-Agent Investigation")
    st.caption("Runs the full pipeline: local risk enrichment → investigator agent → critic agent → guardrails → audit trail.")
    st.caption("Voice fill works in Chrome/Edge — the first time you click a mic, the browser asks for Microphone access. Click **Allow**.")

    api_key = os.environ.get("GEMINI_API_KEY")
    try:
        if not api_key:
            api_key = st.secrets.get("GEMINI_API_KEY")
    except Exception:
        pass

    with st.form("single_form"):
        c1, c2 = st.columns(2)
        with c1:
            # Voice fill for the free-text fields (uses the same Web
            # Speech API mic as the Flagged Events search).
            d1, mic1 = st.columns([5, 1])
            with d1:
                dev_id = st.text_input("Device ID", "POS-TESTDEVICE")
            with mic1:
                render_voice_search_mic("Device ID")
            d2, mic2 = st.columns([5, 1])
            with d2:
                merch_id = st.text_input("Merchant ID", "MER-TESTMERCH")
            with mic2:
                render_voice_search_mic("Merchant ID")
            amount = st.number_input("Transaction Amount (₹)", min_value=0.0, value=500.0)
            retries = st.number_input("Retry Count", min_value=0, value=0, step=1)
        with c2:
            uptime = st.number_input("Device Uptime (hrs)", min_value=0.0, value=200.0)
            ping = st.number_input("Last Ping Gap (sec)", min_value=0.0, value=1.5)
            d3, mic3 = st.columns([5, 1])
            with d3:
                city = st.text_input("Location", "Mumbai")
            with mic3:
                render_voice_search_mic("Location")
            ip_flag = st.selectbox("IP Consistency", [1, 0], index=0)

        submitted = st.form_submit_button("🧠 Launch AI Multi-Agent Investigation", use_container_width=True)

    if submitted:
        if not api_key:
            st.error("No GEMINI_API_KEY found. Set it as an environment variable, or add it under Streamlit Cloud Secrets.")
        elif agent_loop_module is None:
            st.error(
                "The real agent module (agent/agent_loop.py) could not be imported, so no "
                "investigation can be run. Check that agent/, guardrails/, and audit_log/ "
                "are all present alongside dashboard/."
            )
        else:
            with st.spinner("Investigator and critic agents are analyzing telemetry..."):
                try:
                    from google import genai
                    client = genai.Client(api_key=api_key)

                    event = {
                        "transaction_id": str(uuid.uuid4()),
                        "device_id": dev_id,
                        "merchant_id": merch_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "transaction_amount": amount,
                        "retry_count": retries,
                        "device_uptime_hrs": uptime,
                        "last_ping_gap_sec": ping,
                        "geo_city": city,
                        "ip_consistency_flag": ip_flag,
                        "burst_count_5min": 1,
                        "anomaly_raw_score": "N/A (manually entered)",
                    }

                    if tools_load_dataset and os.path.exists(DATA_PATH):
                        tools_load_dataset(DATA_PATH)

                    decision = agent_loop_module.process_event(client, event)

                    act = decision.get("recommended_action", "flag_for_review")
                    st.success("Investigation complete and logged to the audit trail.")
                    st.markdown(f"### 🛡️ Recommended action: `{act.upper()}`")
                    st.write(f"**Fraud pattern:** `{decision.get('fraud_type_guess')}`")
                    st.write(f"**Confidence:** `{decision.get('confidence')}`")
                    st.write(f"**Reasoning:** {decision.get('reasoning_summary')}")
                    if decision.get("critic_summary"):
                        st.caption(f"🛡️ Critic verdict ({decision.get('critic_verdict')}): {decision.get('critic_summary')}")
                    if decision.get("recommended_remediation"):
                        st.info(f"**Remediation:** {decision.get('recommended_remediation')}")
                    st.json(decision)

                    # AI voice: read the investigation outcome aloud.
                    speak_text = (
                        f"Investigation complete. Recommended action: {act}. "
                        f"Fraud pattern: {decision.get('fraud_type_guess', 'unknown')}. "
                        f"Confidence: {decision.get('confidence', 0)}. "
                        f"Reasoning: {decision.get('reasoning_summary', 'No reasoning recorded.')}"
                    )
                    if decision.get("critic_summary"):
                        speak_text += f" Critic verdict: {decision.get('critic_summary')}"
                    if decision.get("recommended_remediation"):
                        speak_text += f" Recommended remediation: {decision.get('recommended_remediation')}"
                    render_speak_button(speak_text)
                except Exception as e:
                    st.error(f"Investigation failed: {e}")


# ============================================================
# 6. VIEW: BATCH INVESTIGATION
# ============================================================
elif nav_option == "⚡ Batch Investigation":
    st.markdown("## ⚡ Batch Investigation")
    st.caption("Upload a CSV, pick an existing one, or run against the currently flagged set.")
    st.caption("The mic fills the CSV-path field — Chrome/Edge only, and the browser must be allowed Microphone access.")

    source = st.radio(
        "Batch source",
        ["Upload CSV", "Select existing CSV", "Use current flagged events"],
        horizontal=True,
    )

    batch_df = None
    if source == "Upload CSV":
        uploaded = st.file_uploader("Upload Telemetry CSV", type=["csv"])
        if uploaded:
            batch_df = pd.read_csv(uploaded)
            st.success(f"Loaded {len(batch_df)} transactions from file.")
    elif source == "Select existing CSV":
        known_csvs = _discover_csv_files()
        st.caption("Pick a CSV already in the project, or type a full path to any file on disk.")
        picked = st.selectbox(
            "CSV file",
            known_csvs or ["(no CSVs found in project)"],
        )
        p1, mic_path = st.columns([5, 1])
        with p1:
            custom_path = st.text_input("Or enter a CSV path", value="")
        with mic_path:
            render_voice_search_mic("Or enter a CSV path")

        chosen = custom_path.strip()
        if not chosen and picked and picked != "(no CSVs found in project)":
            chosen = picked

        if chosen:
            if os.path.exists(chosen):
                try:
                    batch_df = pd.read_csv(chosen)
                    st.success(
                        f"Loaded {len(batch_df)} transactions from "
                        f"{os.path.basename(chosen)}."
                    )
                except Exception as exc:
                    st.error(f"Could not read {chosen}: {exc}")
            else:
                st.warning(f"File not found: {chosen}")
    else:
        if not df_flagged.empty:
            batch_df = df_flagged
            st.success(f"Using {len(batch_df)} currently flagged events.")
        else:
            st.warning("No flagged_events.csv found.")

    if batch_df is not None and not batch_df.empty:
        st.dataframe(batch_df.head(20), use_container_width=True, hide_index=True)
        st.caption(
            "Full batch AI investigation runs one event at a time through the same "
            "investigator + critic pipeline as Single Investigation. Use the run "
            "controls below, or the CLI: `python agent_loop.py --all --limit N` "
            "(the CLI paces calls to stay within the Gemini free-tier rate limit)."
        )

        # AI voice: read the batch outcomes aloud (from the audit log
        # for these transactions when available, else a batch summary).
        if "transaction_id" in batch_df.columns:
            batch_ids = set(batch_df["transaction_id"].astype(str))
            batch_logs = [
                e for e in read_recent_logs(limit=300)
                if str(e.get("transaction_id")) in batch_ids
            ]
            if batch_logs:
                lines = [
                    f"Batch of {len(batch_logs)} investigated events. "
                ]
                for e in batch_logs[-5:]:
                    d = e.get("decision", {})
                    lines.append(
                        f"Event {str(e.get('transaction_id'))[:8]}: "
                        f"recommended {d.get('recommended_action', 'flag for review')}, "
                        f"fraud pattern {d.get('fraud_type_guess', 'unknown')}, "
                        f"confidence {d.get('confidence', 0)}. "
                        f"{d.get('reasoning_summary', '')}"
                    )
                render_speak_button(" ".join(lines))
            else:
                top = batch_df.head(5)
                summary = (
                    f"Batch loaded with {len(batch_df)} flagged events. "
                    f"Top events by risk: "
                )
                parts = []
                for _, row in top.iterrows():
                    parts.append(
                        f"merchant {row.get('merchant_id', 'unknown')}, "
                        f"device {row.get('device_id', 'unknown')}, "
                        f"risk score {row.get('risk_score', 'unknown')}"
                    )
                summary += "; ".join(parts) + ". "
                summary += (
                    "No AI outcomes logged yet for this batch. "
                    "Run the batch investigation to generate decisions."
                )
                render_speak_button(summary)

        st.markdown("---")
        st.markdown("### 🚀 Run batch investigation")
        st.caption(
            "Each event runs through the same pipeline as Single Investigation "
            "(investigator agent → critic → guardrails) and is written to the "
            "audit trail. Budget roughly 30–90s per event; on the Gemini free "
            "tier, 429 rate limits are handled automatically with retry waits."
        )

        rc1, rc2 = st.columns(2)
        with rc1:
            run_limit = st.number_input(
                "Events to investigate",
                min_value=1,
                max_value=int(len(batch_df)),
                value=min(5, int(len(batch_df))),
                step=1,
            )
        with rc2:
            run_delay = st.number_input(
                "Delay between events (sec)",
                min_value=0.0,
                max_value=60.0,
                value=2.0,
                step=0.5,
            )

        run_clicked = st.button(
            "🚀 Run batch",
            type="primary",
            width="stretch",
        )

        if run_clicked:
            batch_api_key = os.environ.get("GEMINI_API_KEY")
            try:
                if not batch_api_key:
                    batch_api_key = st.secrets.get("GEMINI_API_KEY")
            except Exception:
                pass

            if not batch_api_key:
                st.error(
                    "No GEMINI_API_KEY found. Set it as an environment variable, "
                    "or add it under Streamlit Cloud Secrets."
                )
            elif agent_loop_module is None:
                st.error(
                    "The real agent module (agent/agent_loop.py) could not be "
                    "imported, so no investigation can be run."
                )
            else:
                from google import genai
                batch_client = genai.Client(api_key=batch_api_key)
                if tools_load_dataset and os.path.exists(DATA_PATH):
                    tools_load_dataset(DATA_PATH)

                events = batch_df.head(int(run_limit))
                total = int(len(events))

                status = st.status(
                    "Batch investigation running...",
                    expanded=True,
                )
                progress = st.progress(0.0, text=f"0/{total} events")

                results = []
                start_time = time.time()

                for i, (_, row) in enumerate(events.iterrows()):
                    event = row.to_dict()
                    tid = str(event.get("transaction_id", f"event-{i + 1}"))

                    progress.progress(
                        i / total,
                        text=f"Investigating {i + 1}/{total}: {tid}...",
                    )
                    status.write(f"🔍 Investigating `{tid}`")

                    try:
                        decision = agent_loop_module.process_event(
                            batch_client,
                            event,
                        )
                        results.append({
                            "transaction_id": tid,
                            "merchant_id": event.get("merchant_id", ""),
                            "device_id": event.get("device_id", ""),
                            "recommended_action": decision.get(
                                "recommended_action", ""
                            ),
                            "fraud_type_guess": decision.get(
                                "fraud_type_guess", ""
                            ),
                            "confidence": decision.get("confidence", ""),
                            "alert_status": decision.get("alert_status", ""),
                            "reasoning_summary": decision.get(
                                "reasoning_summary", ""
                            ),
                            "critic_summary": decision.get(
                                "critic_summary", ""
                            ),
                            "recommended_remediation": decision.get(
                                "recommended_remediation", ""
                            ),
                        })
                        status.write(
                            f"✅ `{tid}` → "
                            f"`{decision.get('recommended_action', '')}` "
                            f"(confidence {decision.get('confidence', '')})"
                        )
                    except Exception as exc:
                        status.write(f"❌ `{tid}` — failed: {exc}")

                    if i < total - 1 and run_delay > 0:
                        time.sleep(run_delay)

                elapsed = time.time() - start_time
                progress.progress(
                    1.0,
                    text=f"Done — {len(results)}/{total} events "
                         f"in {elapsed:.0f}s",
                )
                status.update(
                    label=f"Batch complete — {len(results)}/{total} events "
                          f"in {elapsed:.0f}s",
                    state="complete",
                    expanded=False,
                )

                if results:
                    st.success(
                        f"Investigated {len(results)} events. All decisions "
                        "logged to the audit trail."
                    )
                    results_df = pd.DataFrame(results)
                    st.dataframe(
                        results_df.drop(
                            columns=[
                                "reasoning_summary",
                                "critic_summary",
                                "recommended_remediation",
                            ]
                        ),
                        hide_index=True,
                        width="stretch",
                    )
                    for r in results:
                        with st.expander(
                            f"📋 {r['transaction_id']} — "
                            f"{r['recommended_action'].upper()}"
                        ):
                            st.write(f"**Reasoning:** {r['reasoning_summary']}")
                            if r["critic_summary"]:
                                st.caption(
                                    f"🛡️ Critic verdict: {r['critic_summary']}"
                                )
                            if r["recommended_remediation"]:
                                st.info(
                                    f"**Remediation:** "
                                    f"{r['recommended_remediation']}"
                                )


# ============================================================
# 7. VIEW: ANALYTICS — computed from the real flagged dataset
# ============================================================
elif nav_option == "📊 Analytics":
    st.markdown("## 📊 Threat Analytics")
    st.caption("Computed from the current flagged_events.csv and transactions.csv — recomputed on refresh, not fixed numbers.")

    if df_flagged.empty:
        st.warning("No flagged_events.csv found. Run detection/anomaly_scorer.py first.")
    else:
        counts = risk_tier_counts(df_flagged)
        a1, a2, a3, a4 = st.columns(4)
        recall_note = "ground-truth recall printed by anomaly_scorer.py at run time"
        a1.metric("Flagged / Total", f"{(flagged_txns/total_txns*100) if total_txns else 0:.1f}%")
        a2.metric("Critical events", counts["CRITICAL"])
        a3.metric("High events", counts["HIGH"])
        a4.metric("Avg risk score", f"{avg_risk_score if avg_risk_score is not None else '—'}")
        st.caption(f"Detector accuracy (recall/precision) is not duplicated here — see {recall_note}.")

        st.markdown("---")
        c_left, c_right = st.columns(2)

        with c_left:
            st.markdown("### Attack Vector Breakdown")
            if "fraud_type" in df_flagged.columns:
                vec_counts = df_flagged["fraud_type"].value_counts()
                st.bar_chart(vec_counts, use_container_width=True)
            elif "reason" in df_flagged.columns:
                vec_counts = df_flagged["reason"].value_counts().head(10)
                st.bar_chart(vec_counts, use_container_width=True)
            else:
                st.info("No fraud-type/reason column in flagged_events.csv to break down.")

        with c_right:
            st.markdown("### Geographic Distribution")
            if "geo_city" in df_flagged.columns:
                geo_counts = df_flagged["geo_city"].value_counts()
                st.bar_chart(geo_counts, use_container_width=True)
            else:
                st.info("No geo_city column in flagged_events.csv.")


# ============================================================
# 8. VIEW: ALERTS — real escalate/soft_hold decisions, not
# invented ones. Count in the label reflects the actual queue.
# ============================================================
elif nav_option == "🔔 Alerts":
    logs = read_recent_logs(limit=200)
    alert_logs = [
        e for e in logs
        if e.get("decision", {}).get("recommended_action") in ("escalate", "soft_hold")
    ]

    st.markdown(f"## 🔔 Active Security Alerts ({len(alert_logs)})")
    st.caption("Real escalate / soft_hold decisions from the audit log — not a simulated feed.")

    if not alert_logs:
        st.success("No active alerts. Run investigations to populate this list.")
    else:
        rows = []
        for e in reversed(alert_logs):
            dec = e.get("decision", {})
            rows.append({
                "Transaction": e.get("transaction_id"),
                "Severity": dec.get("recommended_action", "").upper(),
                "Merchant": e.get("merchant_id"),
                "Device": e.get("device_id"),
                "Confidence": dec.get("confidence"),
                "Alert status": dec.get("alert_status", "n/a"),
                "Time": str(e.get("logged_at", ""))[:19],
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ============================================================
# 9. VIEW: REPORTS — built from real computed values already
# in memory (telemetry dict), not separate hardcoded tables.
# ============================================================
elif nav_option == "📄 Reports":
    st.markdown("## 📄 Reports")
    st.caption("Generated from the current dataset and audit log.")

    r1, r2 = st.columns(2)

    with r1:
        st.markdown("### Daily Risk Summary")
        counts = risk_tier_counts(df_flagged)
        summary_report = pd.DataFrame([
            {"Metric": "Date", "Value": datetime.now().strftime("%Y-%m-%d")},
            {"Metric": "Total Transactions", "Value": f"{total_txns:,}"},
            {"Metric": "Flagged Transactions", "Value": f"{flagged_txns:,}"},
            {"Metric": "Critical Events", "Value": counts["CRITICAL"]},
            {"Metric": "High Events", "Value": counts["HIGH"]},
            {"Metric": "Pending Human Review", "Value": pending_review},
            {"Metric": "Average Risk Score", "Value": avg_risk_score if avg_risk_score is not None else "n/a"},
        ])
        st.dataframe(summary_report, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Download Daily Report (CSV)",
            data=summary_report.to_csv(index=False).encode("utf-8"),
            file_name=f"fraud_summary_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with r2:
        st.markdown("### Merchant Risk Scorecard")
        if not df_flagged.empty and "merchant_id" in df_flagged.columns and "risk_score" in df_flagged.columns:
            merchant_report = (
                df_flagged.groupby("merchant_id")
                .agg(flagged_count=("risk_score", "count"), avg_risk=("risk_score", "mean"))
                .reset_index()
                .sort_values("avg_risk", ascending=False)
                .head(15)
            )
            merchant_report["avg_risk"] = merchant_report["avg_risk"].round(1)
            st.dataframe(merchant_report, use_container_width=True, hide_index=True)
            st.download_button(
                "⬇️ Download Merchant Scorecard (CSV)",
                data=merchant_report.to_csv(index=False).encode("utf-8"),
                file_name="merchant_risk_scorecard.csv",
                mime="text/csv",
                use_container_width=True,
            )
        else:
            st.info("No flagged data with merchant_id/risk_score to summarize.")


# ============================================================
# 10. VIEW: SETTINGS — actually wired to config.json, which
# anomaly_scorer.py / alert_cooldown.py / agent_loop.py can read.
# ============================================================
elif nav_option == "⚙️ Settings":
    st.markdown("## ⚙️ Pipeline Configuration")
    st.caption("These settings are written to config.json and read by the actual backend scripts on their next run.")

    cfg = load_config()

    with st.form("settings_form"):
        s1, s2 = st.columns(2)

        with s1:
            st.markdown("#### AI Model")
            model_choice = st.selectbox(
                "Gemini model",
                ["gemini-3.5-flash-lite", "gemini-2.5-flash-lite", "gemini-3.6-flash"],
                index=0 if cfg["model"] not in ["gemini-2.5-flash-lite", "gemini-3.6-flash"] else
                      ["gemini-3.5-flash-lite", "gemini-2.5-flash-lite", "gemini-3.6-flash"].index(cfg["model"]),
            )
            min_escalate_conf = st.slider("Minimum confidence for escalate", 0.5, 1.0, float(cfg["min_escalate_confidence"]))

        with s2:
            st.markdown("#### Detection sensitivity")
            contamination = st.slider("Isolation Forest contamination", 0.01, 0.20, float(cfg["contamination"]))
            cooldown_mins = st.number_input("Alert cooldown window (minutes)", value=int(cfg["cooldown_minutes"]), min_value=1)

        save_btn = st.form_submit_button("💾 Save configuration", use_container_width=True)

    if save_btn:
        new_cfg = {
            "model": model_choice,
            "contamination": contamination,
            "cooldown_minutes": cooldown_mins,
            "min_escalate_confidence": min_escalate_conf,
        }
        save_config(new_cfg)
        st.success(
            f"Saved to config.json. Next run of anomaly_scorer.py will use "
            f"contamination={contamination}, agent_loop.py will use model='{model_choice}', "
            f"and the guardrail/cooldown layers will require ≥ {min_escalate_conf} "
            f"confidence to escalate with a {cooldown_mins}-minute alert cooldown."
        )
        st.json(new_cfg)