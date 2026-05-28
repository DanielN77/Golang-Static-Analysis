import os
import shutil
import subprocess

# List of Go projects to analyze
PROJECTS = [
    "https://github.com/gin-gonic/gin.git",
    "https://github.com/golang/example.git",
    "https://github.com/spf13/cobra.git",
    "https://github.com/BhairaviSanskriti/Order-Food.git",
    "https://github.com/edoardottt/gonesis.git",
    "https://github.com/gorilla/mux.git",
    "https://github.com/robfig/cron.git",
    "https://github.com/uber-go/goleak.git",
    "https://github.com/go-gorm/gorm.git",
    "https://github.com/spf13/viper.git",
    "https://github.com/droxey/goslackit.git",
    "https://github.com/Prince-1501/url-shortner.git",
    "https://github.com/jaavier/dotenv.git",
    "https://github.com/cjbearman/sim6502.git",
    "https://github.com/gopher-lego/skeleton.git",
    "https://github.com/dgraph-io/badger.git",
    "https://github.com/allegro/bigcache.git",
    "https://github.com/go-pg/migrations.git",
    "https://github.com/pressly/goose.git",
    "https://github.com/sqlc-dev/sqlc.git",
    "https://github.com/jmoiron/sqlx.git"
]

BASE_DIR = "analysis_projects"
REPORTS_DIR = "../reports"
ANALYZER_SCRIPT = "main.py"

def run_command(command, cwd=None):
    print(f"Running: {' '.join(command)}")
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
    return result.returncode

def clone_project(repo_url):
    repo_name = repo_url.split("/")[-1].replace(".git", "")
    project_path = os.path.join(BASE_DIR, repo_name)
    # Remove old clone if it exists
    if os.path.exists(project_path):
        shutil.rmtree(project_path)
    run_command([
        "git",
        "clone",
        repo_url,
        project_path
    ])
    return repo_name, project_path

def run_analysis(repo_name, project_path):
    repo_report_dir = os.path.join(REPORTS_DIR, repo_name)
    os.makedirs(repo_report_dir, exist_ok=True)
    # Run our tool
    custom_sarif_path = os.path.join(
        repo_report_dir,
        "custom-report.sarif"
    )
    analyzer_result = run_command([
        "python3",
        ANALYZER_SCRIPT,
        project_path,
        "--sarif",
        "--output",
        custom_sarif_path
    ])

    if analyzer_result != 0:
        print(f"\nSKIPPING! Analyzer failed for {repo_name}\n")

        if os.path.exists(project_path):
            shutil.rmtree(project_path)

        if os.path.exists(repo_report_dir):
            shutil.rmtree(repo_report_dir)

        return

    # Run govulncheck
    govulncheck_output = os.path.join(
        repo_report_dir,
        "govulncheck-report.sarif"
    )
    with open(govulncheck_output, "w") as sarif_file:
        print(f"govulncheck on {repo_name}")
        # govulncheck -format sarif ./...
        subprocess.run( 
            [
                "govulncheck",
                "-format",
                "sarif",
                "./..."
            ],
            cwd=project_path,
            stdout=sarif_file,
            stderr=subprocess.PIPE,
            text=True
        )

    print(f"Reports saved to {repo_report_dir}")

def main():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    for repo_url in PROJECTS:
        try:
            repo_name, project_path = clone_project(repo_url)
            run_analysis(repo_name, project_path)

        except Exception as e:
            print(f"\nERROR! Failed processing {repo_url}")
            print(e)


if __name__ == "__main__":
    main()