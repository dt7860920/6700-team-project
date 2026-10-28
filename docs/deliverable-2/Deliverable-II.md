# DSAN 6700 Final Project — Deliverable II Midpoint Check-In

**Project:** Operation: Negative One

**Team members:** Sazan Khalid, Kenedy Ducheine, Junyi Tang, Jeffrey Pinarchick

**GitHub repository:** <https://github.com/dt7860920/6700-team-project>

**Jetstream2 application:** <http://149.165.168.237:8000> *(verify before submission)*

> Submission note: Each team member must individually upload the group's final
> midpoint check-in as a PDF on Canvas.

## 1. Project overview and current working skeleton

Operation: Negative One is a defensive code-analysis application intended to
help security teams examine open-source code for potentially exploitable
vulnerabilities. In the intended workflow, a user submits source code for
analysis and receives structured findings containing the affected file and
line, the relevant CWE category, an explanation of the potential risk, a
triggering example, and, when available, a proposed patch.

The current midpoint prototype demonstrates part of this workflow. The
`streamlit-ui` branch contains a Streamlit interface that accepts a ZIP archive,
starts a mock analysis job, displays progress, and presents simulated findings.
This allows the team to test the user experience and expected job-API contract
before connecting the real analysis pipeline. The repository's `main` branch
also contains a FastAPI foundation with a health endpoint, configurable model
placement, environment-based settings, automated tests, and Docker Compose
deployment files.

The project is therefore a **walking skeleton rather than an MVP**. The user
interface, service foundation, configuration, deployment path, and expected
data contract are represented, but the Streamlit job flow is not yet connected
to the FastAPI service and the real security analytic is not yet integrated.

### Midpoint implementation status

| Component | Midpoint status |
| --- | --- |
| Streamlit ZIP-upload interface | Implemented on the `streamlit-ui` branch |
| Mock job progress and sample findings | Implemented on the `streamlit-ui` branch |
| FastAPI service and health endpoint | Implemented on `main` |
| Environment-based model placement | Implemented on `main` |
| Docker and Docker Compose foundation | Implemented on `main` |
| Jetstream2 FastAPI deployment | Deployed; URL must be verified before submission |
| Streamlit-to-FastAPI `/jobs` integration | Planned/in progress |
| Hunter, verifier, and patching pipeline | Proposed; not yet integrated |

## 2. Solution architecture

![Operation: Negative One solution architecture](solution-architecture.png)

**Figure 1. Solution architecture for Operation: Negative One.** The diagram
organizes the application around process, execution, and state while separating
the user-facing workflow from the analysis and deployment foundation.

- **Process:** build the application, use it to analyze submitted source code,
  and monitor its operation.
- **Execution:** move a submission through the user interface, job API,
  security-analysis workflow, and results display.
- **State:** keep source control and deployment configuration persistent while
  treating uploaded code, job status, findings, and proposed patches as
  temporary analysis state.

## 3. Technical architecture

> **TODO — technical architecture diagram:** Insert the team's proposed
> technical architecture showing the website/Streamlit interface, ZIP upload,
> Jetstream2 GPU boundary, read-only sandbox, Qwen hunter, independent verifier,
> patch model, unified-diff output, and results returned to the user. Clearly
> label the model pipeline as proposed or planned until it is integrated.

**Figure 2. Proposed technical architecture for Operation: Negative One.**

<!-- Add the technical diagram image here after its PR is reviewed and merged. -->

## 4. Application flow and API contract

The midpoint Streamlit prototype uses a mock client to demonstrate the
following job lifecycle:

1. The user uploads a ZIP archive of code they are permitted to analyze.
2. The interface validates the archive and submits an analysis job.
3. The interface polls the job status and displays progress.
4. The backend returns structured findings after the job completes.
5. The interface displays each finding and offers a patch download when a patch
   is available.

The planned backend contract uses `POST /jobs`, `GET /jobs/{job_id}`,
`GET /jobs/{job_id}/results`, and `DELETE /jobs/{job_id}`. These job endpoints
are documented on the `streamlit-ui` branch but are not yet implemented in the
FastAPI service on `main`.

## 5. Deployment and configuration

The FastAPI foundation is containerized and deployed to Jetstream2 with Docker
Compose. Environment variables or a `.env` file control application settings
and model placement. The Docker configuration publishes only the application
port, `8000`. The current Jetstream2 deployment demonstrates the API deployment
foundation; it does not yet represent the complete Streamlit security-analysis
application.

Before submission, the team must:

- [ ] Verify that the Jetstream2 application URL is reachable.
- [ ] Confirm whether the midpoint demonstration will expose FastAPI, Streamlit,
      or both.
- [ ] Confirm that only the intended application port is publicly accessible.
- [ ] Add a screenshot showing meaningful user input and output.

## 6. Analytic and model placement

The existing FastAPI foundation uses a configurable `ModelClient` that selects
either a local in-process backend or a remote HTTP model service through
environment settings. The security-specific analytic is still proposed. The
current technical design uses a Qwen-based hunter to identify candidate
exploits, a second model to verify candidates, and a patch model to produce a
unified diff for verified findings. Until that pipeline is implemented, the
Streamlit prototype uses simulated findings from its mock backend.

## 7. Evaluation and baseline

The midpoint baseline should measure both effectiveness and efficiency. Results
must be added after the team runs the agreed evaluation dataset.

| Measure | Baseline method | Midpoint result |
| --- | --- | --- |
| End-to-end workflow | Upload a valid ZIP and obtain mock findings | Demonstrated with mock backend |
| API health | Request `GET /health` on Jetstream2 | **TODO: record result and date** |
| Detection precision | Manually labeled vulnerable and clean examples | **TODO** |
| False-positive rate | Compare verified findings with labeled examples | **TODO** |
| Analysis latency | Measure submission-to-results time | **TODO** |
| Resource usage | Observe Jetstream2 CPU/GPU and memory use | **TODO** |

The mock workflow validates interface behavior, but it cannot establish the
accuracy of the future security analytic. Analytic accuracy must be evaluated
after the hunter and verifier are connected.

## 8. Safety and limitations

- Uploaded repositories may contain untrusted content and must be handled in an
  isolated, read-only environment without executing arbitrary project code.
- Model-generated findings and patches may be incorrect or incomplete.
- License validation and repository-ingestion rules still need to be finalized.
- The midpoint Streamlit results are simulated and do not demonstrate real
  vulnerability detection.
- The current Jetstream2 deployment is the FastAPI foundation, not the complete
  security-analysis workflow.
- GPU availability, model latency, and repository size may limit scalability.
- Secrets, API keys, repository contents, and model-service URLs must not be
  committed to Git or written to application logs.

## 9. Team collaboration and evidence

The team organizes development through GitHub issues, branches, pull requests,
and reviews. Documentation and figures are also submitted through PRs so each
contribution remains reviewable.

| Contribution | Evidence |
| --- | --- |
| Solution architecture and Deliverable II outline | PR #18 |
| Streamlit walking-skeleton interface | `streamlit-ui` branch / associated PR |
| Technical architecture | **TODO: add teammate's PR** |
| Deployment verification | **TODO: add issue or PR** |
| Evaluation results | **TODO: add issue or PR** |

## 10. Work remaining before submission

- [ ] Review and merge the solution-architecture PR.
- [ ] Add and review the technical-architecture PR.
- [ ] Verify the Jetstream2 URL and capture deployment evidence.
- [ ] Add a screenshot of meaningful input and output.
- [ ] Record baseline evaluation results.
- [ ] Complete the safety and limitations review.
- [ ] Reconcile all terminology across the diagrams and text.
- [ ] Export the final document as a PDF with all team members' names at the top.
- [ ] Have each team member upload the same group PDF to Canvas.
