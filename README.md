# BLOODHOUND

An AI agent that hunts a hidden attacker in security logs. It writes its own
queries, runs them against real Elasticsearch, reconstructs the attack timeline,
maps MITRE ATT&CK techniques, and streams the whole investigation live to a
detective-board UI.

---

# PART 1 — SETUP FROM SCRATCH

Follow these in order. Commands are for **Windows PowerShell** (use `py`). On
Mac/Linux replace `py` with `python3`.

## 1. Install the tools (once)
You need three things installed on your computer:
- **Python 3.11+** — https://www.python.org/downloads/ (tick "Add to PATH")
- **Docker Desktop** — https://www.docker.com/products/docker-desktop/ (open it, leave it running)
- A code editor like **VS Code** (optional but helpful)

Check Python works:
```
py --version
```

## 2. Install the Python libraries (once)
In the project folder, run:
```
py -m pip install "elasticsearch>=8,<9" fastapi uvicorn pydantic langgraph google-genai
```

## 3. Get a free Gemini API key (for the real AI brain)
- Go to https://aistudio.google.com/apikey and create a key.
- Set it in PowerShell (do this each time you open a new terminal):
```
$env:GOOGLE_API_KEY="paste-your-key-here"
```
You can skip this for now — the project runs without it in "mock" mode.

## 4. Make the data
This creates the fake logs with the attack hidden inside:
```
py -m generate_logs
```
You get `logs.ndjson` (the logs) and `ground_truth.json` (the answer key).

## 5. Test the logic with NO Docker (fastest first win)
These read the file directly — no cluster needed:
```
py -m search_layer      # finds the attacker, ends with "mark.chen -> MATCH"
py -m agent             # 10 hunts, must reach the exfil in <=4 queries each
py -m timeline          # builds the timeline + MITRE, prints PASS x5
```
If these work, your whole brain/logic layer is good.

## 6. Start real Elasticsearch (needs Docker running)
```
docker compose up -d              # starts Elasticsearch (wait ~30 sec)
curl http://localhost:9200        # should print JSON with a version number
py -m ingest                      # loads logs.ndjson into Elasticsearch
py -m check_templates             # runs all 14 queries on the cluster, want all OK
```
Stop it later with: `docker compose down`

## 7. Run the live UI (the demo)
```
py -m uvicorn server:app --reload --port 8000
```
Open **http://localhost:8000** in your browser and click **Begin Hunt**.
On the start screen you can choose:
- **mock / gemini** = fake brain (instant, free) or real Gemini brain
- **file / elastic** = read the file or the live cluster

Rehearse on **mock + file** (instant, no key, no Docker). For the real demo use
**gemini + elastic**.

## Quick troubleshooting
- `python3 not found` → use `py` instead.
- `py -m ingest.py` fails → drop the `.py`, it's `py -m ingest`.
- Docker won't start ES → Docker Desktop → Settings → Resources → give it 2GB+ RAM.
- UI page is blank/404 → you skipped step 0; `index.html` must be in `static/`.
- Live query returns 0 → your `logs.ndjson` has no attack; re-run step 4, then step 6.

---

# PART 2 — WHAT EACH FILE DOES

```
BLOODHOUND/
├── generate_logs.py     STEP 1: makes the fake logs (500k events) with the
│                                 attack hidden in noise + ground_truth.json
├── logs.ndjson          the generated logs (the data everything runs on)
├── ground_truth.json    the answer key (attacker, timeline, MITRE) — used to
│                                 check the agent is right; the agent never sees it
│
├── docker-compose.yml   STEP 2: starts Elasticsearch on your machine (1 command)
├── mapping.json         tells Elasticsearch each field's type (used by ingest)
├── ingest.py            loads logs.ndjson into Elasticsearch
│
├── queries.py           the 14 validated query templates + execute(). The AI
│                                 picks a template and fills blanks — it never
│                                 writes raw queries, so they can't break.
├── check_templates.py   runs all 14 templates on the live cluster, prints OK/FAIL
├── search_layer.py      the stronger engine: baselining, real impossible-travel
│                                 (speed math), and groups signals into incidents.
│                                 Runs offline against the file.
│
├── agent_brains.py      the swappable parts: the BRAIN (GeminiLLM real /
│                                 MockLLM for testing) and the EXECUTOR
│                                 (LiveExecutor = Elasticsearch / OfflineExecutor = file)
├── agent.py             the reasoning loop: hypothesis -> query -> read result
│                                 -> decide next -> repeat. Capped at 6 steps.
│                                 `py -m agent` runs the offline reliability test.
├── agent_stream.py      same loop, but YIELDS each step as an event so the UI
│                                 can stream it live (thinking, query, raw JSON,
│                                 finding, graph edge, timeline pin).
│
├── timeline.py          builds the chronological attack timeline from real
│                                 events, then maps behaviours to MITRE technique
│                                 IDs. `py -m timeline` proves 5-run consistency.
│
├── server.py            the web server (FastAPI). Streams the hunt to the
│                                 browser over SSE. Run with uvicorn (step 7).
├── static/
│   └── index.html       the detective-board UI: 3 live panels (reasoning,
│                                 lateral-movement graph, timeline). One file,
│                                 no build step.
│
├── test_gemini.py       a small script you wrote to check your Gemini key works
├── plan.pdf             the original project plan
└── README.md            this file
```

## The order it all flows
```
generate_logs.py  ->  logs.ndjson
                          |
                   ingest.py -> Elasticsearch
                          |
   agent.py / agent_stream.py  (brain from agent_brains.py)
                          |
                   queries.py  -> runs templates -> results
                          |
                   timeline.py -> timeline + MITRE
                          |
        server.py + static/index.html  -> live UI
```

## One-line summary of each runnable command
```
py -m generate_logs      make the data
py -m search_layer       prove the hunt logic (offline)
py -m agent              prove the loop reaches the exfil (offline)
py -m timeline           prove timeline + MITRE (offline)
py -m ingest             load data into Elasticsearch
py -m check_templates    verify all 14 queries on the cluster
py -m agent_stream       preview the event stream (offline)
py -m uvicorn server:app --reload --port 8000    run the live UI
```
