# Demo video script (2 minutes)

The four "LIVE AT THE FINALE" demos from slide 4, in order, with exact clicks. Record at 1400×900 or larger.

## Before recording (5 minutes)

1. Start the Ollama app (tray icon) and warm the model once - the first call loads it into memory (~10 s):
   ```powershell
   & "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" run llama3:8b "say ok"
   ```
2. Build the UI if you changed it: `cd frontend; npm run build; cd ..`
3. Start the demo (fresh data every time):
   ```powershell
   conda activate logsync
   python -m logsync demo
   ```
4. Open http://127.0.0.1:8000 and **wait about 60 seconds** so every family, a few blocked lines and a
   few hundred dead-lettered Juniper SRX lines have arrived.
5. **Draft the pack once before recording** (Pack editor → *Draft a parser*): drafting takes about a minute
   on CPU. Either record it and speed that part up in editing, or cut from the click to the result.

## Script

| time | screen | do | say |
|---|---|---|---|
| 0:00 | Dashboard | nothing - let the numbers move | "Firewalls from five vendors, five formats - syslog, key-value, CSV, CEF, LEEF, JSON - normalized live into one OCSF-aligned schema. Every event archived and sealed before it is parsed." |
| 0:12 | Dashboard | point at the Evidence log panel | "Every two seconds the archive is sealed into a signed Merkle tree with an RFC 3161 timestamp." |
| 0:20 | Event inspector | *accepted* filter → click a Suricata or FortiGate event → hover `src_endpoint.ip` in the table | "Can I prove where this field came from? These exact bytes, these declared transforms, this signed parser version." (**demo 3**) |
| 0:40 | Verify | *Verify event* | "Verification trusts nothing stored: it re-reads the archived bytes and re-derives everything. Five checks pass." |
| 0:48 | Verify | *Alter one archived byte, then verify* | "Now I change one byte in the archive, like an attacker would. Archive, provenance and Merkle checks all fail - the exact byte is shown." (**demo 4**) |
| 0:58 | Verify | *Restore the original byte* | "Restored - verified again." |
| 1:03 | Dashboard | point at the *Unknown* row and the drift radar | "A new device, a Juniper SRX, sends a format we have no parser for. Its lines are not lost - archived, sealed, dead-lettered." |
| 1:10 | Pack editor | sample is pre-filled from the dead letters → *Draft a parser* (cut the wait) | "Drain mines the structure, our offline Llama 3 names the fields - no cloud, no internet. Then deterministic tests decide: held-out match rate, round-trip, fuzzing, sandbox differential. All pass." |
| 1:30 | Pack editor | *Review field mapping* → fix one wrong suggestion (e.g. the protocol number → `connection_info.protocol_num`) → *Approve & sign* | "The analyst corrects what the model got wrong and approves. The pack is signed, hot-loaded - and every archived dead-letter line is re-parsed from its original bytes." (**demo 2**) |
| 1:45 | Dashboard | dead-letter drops, Juniper appears as a source | "No code, no YAML by hand, no restart." (**demo 1**) |
| 1:52 | - | - | "Air-gap native, containerised, Kafka-scaled, every field provable. LogSync." |

## If something goes wrong

* *backend offline* badge: the `logsync demo` window was closed - start it again.
* Draft says *drain (deterministic fallback - model unavailable)*: Ollama is not running. The pack still works; start
  Ollama and draft again for the LLM version.
* The gate fails on a draft: too few distinct lines have arrived yet - wait a minute and draft again.
