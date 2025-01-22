# Software Composition Analysis by Surface Security  

## sbom-repo
The SBOM repo has data from **OSV.dev** as it's main source of truth and we're using it as a dependency vulnerability database.

The SBOM repo is a complementary module of Surface SCA is within the main surface app, docs and code are available in https://github.com/surface-security/surface/blob/sca/surface/sca. You can use it solo or via pypi as a python application.


### Database Source

**OSV.dev** is an open-source vulnerability database and triage infrastructure project, designed to help both open-source maintainers and consumers of open-source software effectively identify and address security vulnerabilities. It aims to provide precise vulnerability information in a way that is both easily accessible and actionable for developers and users of open-source software. It achieves this by automating the triage of vulnerabilities and maintaining a database where vulnerabilities are directly linked to exact affected package versions, rather than relying on the more traditional, often vague, vulnerability descriptions.
The vulnerability database and the tools provided by OSV.dev are continuously updated to reflect **new vulnerabilities**, **improved triage mechanisms**, and **evolving best practices** in software security. This ensures that using **OSV.dev** every project we scan will always be equipped with the latest in security intelligence.

**SBOM repo** is configured to be a stand alone module, which means, it's a vulnerability database, currently it's importing vulnerabilities from OSV.DEV, but in theory it could be importing from anywhere else.

We've configured it `management/commands/resync_vulnerabilities.py`. Where we import the vulnerabilities from OSV.DEV and create a Vulnerability object for it.


### Process

By uploading an SBOM into the **SBOM repo**, we're able to quickly identify known **vulnerabilities** within software dependencies. This rapid identification allows for quicker remediation efforts, thereby reducing the window of exposure to potential exploits.

We use the concept of **purl** to manage and track the dependencies. A "purl" stands for "Package URL." It's a standardized way to identify and locate a software package within a package management system or ecosystem. The concept of purls is designed to simplify the process of referring to software packages across different programming languages, package managers, and packaging conventions. More in [Pypi](https://pypi.org/project/packageurl-python/).

The **SBOM repo**, will save the SBOM for each app/repo plus information about which of these dependencies are vulnerable and details about it. The SBOM would be imported then into Surface for both visibility and track of both dependencies and vulnerabilities.

Once we receive a **SBOM** we check for vulnerabilities within our Vulnerability Database and return a `.json`. That ´.json` will be cleaned and prepared to create everything we need for a final sbom to import into our Application where we will display and track every dependency and vulnerability, along side several other features. More in [Surface SCA](https://github.com/surface-security/surface/sca).


### How to run it

The **SBOM repo** is pypi package. You can install it using `pip install django-sbomrepo` within your django application. Make sure you include the `sbomrepo` in your `INSTALLED_APPS` in your `settings.py` file and update your `urls.py` file to include the `sbomrepo` urls.

### Features

- **Import SBOM**: `curl -F 'file=@./sbom.json' "http://localhost:8000/sbomrepo/v1/sbom?repo=${{GIT_URL}}&branch=${{GIT_BRANCH}}&main_branch={branch}"`
- **Get SBOM**: `curl "http://localhost:8000/sbomrepo/v1/sbom/<serial_number>"`
- **Get SBOM and Vulnerabilities**: `curl "http://localhost:8000/sbomrepo/v1/sbom/<serial_number>?vuln_data=true"`
- **List All SBOMs**: `curl "http://localhost:8000/sbomrepo/v1/sbom/all"`
- **Delete SBOMs**: `curl -X DELETE "http://localhost:8000/sbomrepo/v1/sbom/delete"`
- **Reimport SBOM**: `curl -X POST "http://localhost:8000/sbomrepo/v1/sbom/<serial_number>/reimport"`
- **Get Vulnerability**: `curl "http://localhost:8000/sbomrepo/v1/vulnerability/<id>"`
- **Get Ecosystems**: `curl "http://localhost:8000/sbomrepo/v1/ecosystems"`
