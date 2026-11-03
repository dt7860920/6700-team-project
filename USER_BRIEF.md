# User Brief: Operation: Negative One (ONO)

**Who is the user?** A developer or security engineer. They are interested in
finding the vulnerabilities in a repo they are authorized to fix, along with patches for
them.

**Where should the user go?** Open the app at <http://149.165.154.219:8080/ui/>. The
[README](https://github.com/dt7860920/6700-team-project/blob/main/README.md) explains
the project and the API.

**How should the user get started?** First, choose **snippet**, keep the example code,
and click **Analyze**. Next, choose **vulpy** or **pygoat** and click **Analyze**. A
full scan can take several minutes, and the progress card shows each stage as it runs.
Then read each finding card the way a reviewer would: is the flagged line really
vulnerable, and is the CWE correct?

**What can the skeleton do and not do?** It scans four approved targets. It runs a
static scanner, then an AI agent (Qwen2.5-Coder-7B) that reads the code in a sealed
sandbox. Each finding lists its CWE, severity, file and line, and the path from user
input to the flawed line. It cannot yet prove that a finding is real or that a fix
works, so every finding is marked unverified and most have no patch. It cannot scan
other repositories or URLs. It handles only a few scans at once. Expect false alarms
and some wrong line numbers.

**What feedback are we seeking?** Tell us which findings were real, which were false,
and which were labeled wrong. Tell us whether the finding cards and the "verified" flag
made sense without help, and whether the wait felt acceptable. Tell us what a finding
would need before you would act on it. Add your feedback as an issue in the
[GitHub repo](https://github.com/dt7860920/6700-team-project/issues).
