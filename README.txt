# OpenLoop Agent: Capabilities and Usage Guide

Welcome to the OpenLoop Agent. This document outlines every agentic capability built into the system and provides a comprehensive guide on how to use them.

## 🚀 Core Agentic Capabilities

The agent is designed to autonomously interact with Windows applications by combining advanced LLM reasoning with native UI automation and stealth techniques.

### 1. The Agent Loop (Snapshot \u002D\u003E Plan \u002D\u003E Execute)
- **UI Inspector**: Automatically generates a highly structured JSON tree of UI elements of the target application.
- **Planner Agent**: Analyzes the parsed UI JSON and user goals, then interfaces with an LLM to dynamically generate a step-by-step execution plan.
- **Executor Agent**: Interprets the Planner's output and systematically executes the required actions on the target application.

### 2. Intelligent UI Automation \u0026 Fallbacks
- **Native Windows UI Automation (UIA)**: Prioritizes deep integrations using patterns like `SelectionItemPattern` and `ExpandCollapsePattern` for robust interaction with list and tree controls.
- **Mouse \u0026 Keyboard Simulation**: Seamlessly falls back to simulating precise mouse clicks and keystrokes when native UIA patterns are unavailable.

### 3. Autonomy \u0026 Process Management
- **Auto-Attach \u0026 Cold Start**: The agent can automatically detect and attach to the foreground window seamlessly without any manual intervention.
- **Process Selector UI**: A dedicated interface to list running processes manually and attach to a specific target window dynamically.

### 4. Remote Control Integrations
- **Telegram Remote Control**: Control the agent entirely via Telegram messages. You can provide your own bot token and chat ID to instruct the agent, select processes remotely, and receive real-time progress/status updates directly in your chat.
- **Web Interface (Vercel)**: A Vercel-hosted Next.js web remote control integrated with Vercel KV (Upstash Redis) that the agent polls for commands, allowing you to orchestrate the agent from any browser.

### 5. Multi-Model LLM Support
The agent is highly flexible and can route intelligence through various state-of-the-art AI providers. Keys can be hardcoded or dynamically entered:
- Gemini
- OpenAI
- Anthropic (Claude)
- DeepSeek
- Moonshot (Kimi)
- OpenRouter
- Ollama (Local AI)

---

## 🛠️ How to Use the Agent

### 1. Installation & Setup
**Quick Install (Recommended)**
Open PowerShell as Administrator and run the following command to download and install OpenLoop automatically:
```powershell
powershell -Command "iwr -useb https://openloop.sh/install.ps1 | iex"

```

**Manual Build**
1. Build the application using the provided build script (e.g., run `build_win32.bat` in a Developer Command Prompt).
2. Ensure the generated executable (`example_win32_directx11.exe`) and required dependencies (like `MinHook.x64.dll`) are in the `Debug` or `Release` directory.
3. Launch the application (e.g., `Debug\example_win32_directx11.exe`). You will be greeted by the primary UI.
4. **Select an AI Provider**: Go to **Settings** and choose your preferred AI provider (e.g., Gemini, OpenAI). Enter your API key if it isn't already hardcoded in `main.cpp`.

### 2. Targeting an Application
- **Auto-Attach**: Simply bring your target application to the foreground, and the agent will detect it.
- **Manual Attach**: Click the **Process Selector** to view all running processes and explicitly map the agent to your target.

### 3. Running the Agent (Local)
1. In the agent's chat input box, type your goal (e.g., \"Like the first post on this page\" or \"Extract data from this table\").
2. Press **Enter** or the **Run Agent** (Send) button.
3. The UI will disable input while the agent works, transitioning through the **Snapshot \u002D\u003E Plan \u002D\u003E Execute** cycle.

### 4. Controlling Agent Execution
- **Pause/Resume**: Use the **Screenshot** button (repurposed for agent control) to pause or resume execution.
- **Stop**: Click the **Stop Agent** (repurposed from Inspect) button to halt the current plan immediately.

### 5. Using Remote Control (Telegram)
1. Go to **Settings** and input your **Telegram Bot Token** and **Chat ID**.
2. Send a message to your bot via the Telegram app with your instructions.
3. The agent will receive the command, list available processes if needed, attach, execute the task, and reply with status updates directly to your phone.

### 6. Using Hotkeys
The agent supports global hotkey bindings for deep integration:
- Customize hotkeys in the settings menu for actions like **Toggle UI visibility**, **Pause/Resume**, and **Stop Agent**.

### 7. Reviewing History
- Toggle **Chat History** to view numbered, date-organized folders of your past interactions and the agent's actions for auditing and debugging.
