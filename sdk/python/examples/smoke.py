"""Explicit transfer and lift-job smoke test against a running loopback hydird.

Usage: python smoke.py ENDPOINT TOKEN_FILE TRUSTED_ELF SYMBOL OUTPUT_DIR
"""

import sys
from pathlib import Path

from hydir_sdk import HydirClient


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit(__doc__)
    endpoint, token_file, binary, symbol, output_dir = sys.argv[1:]
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    with HydirClient(endpoint, token_file) as client:
        discovery = client.discover()
        assert discovery.native_elf_import and discovery.durable_lift_jobs
        project = client.create_project("Python SDK smoke")
        uploaded = client.upload_binary(project.project_id, project.revision, binary)
        spec = client.inspect(project.project_id, uploaded.revision)
        assert spec["binary_sha256"] == uploaded.binary_sha256
        cfg = client.recover_cfg(project.project_id, uploaded.revision, symbol)
        assert cfg["blocks"]
        direct_ir = client.lift(project.project_id, uploaded.revision, symbol, assume_u64x2=True)
        transform_report, transform_artifacts = client.transform(
            project.project_id, uploaded.revision, symbol,
            "instcombine,sccp,simplifycfg,dce",
            assume_u64x2=True, trusted_fixture=True,
        )
        assert transform_report["llvm_verified"] is True
        assert transform_artifacts["raw.ll"] == direct_ir
        transformed_revision = uploaded.revision + 1
        assert client.get_project(project.project_id).revision == transformed_revision
        for name, content in transform_artifacts.items():
            client.export_artifact(content, output / name)
        analysis = client.analyze(project.project_id, transformed_revision)
        assert analysis["binary_sha256"] == uploaded.binary_sha256
        job = client.start_lift_job(
            project.project_id, transformed_revision, symbol, assume_u64x2=True,
            idempotency_key="python-sdk-smoke-lift-1",
        )
        replay = client.start_lift_job(
            project.project_id, transformed_revision, symbol, assume_u64x2=True,
            idempotency_key="python-sdk-smoke-lift-1",
        )
        assert replay.job_id == job.job_id
        states = [event.state for event in client.job_events(project.project_id, job.job_id)]
        assert states[0] == "queued" and states[-1] == "succeeded", states
        job = client.get_job(project.project_id, job.job_id)
        job_ir = client.get_artifact(project.project_id, job.artifact_sha256)
        assert job_ir == direct_ir
        client.export_artifact(job_ir, output / "lifted.ll")
        print(
            f"Python SDK passed: project={project.project_id} revision={transformed_revision} "
            f"blocks={len(cfg['blocks'])} summaries={len(analysis['functions'])} "
            f"events={len(states)}"
        )


if __name__ == "__main__":
    main()
