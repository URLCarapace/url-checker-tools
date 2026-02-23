########################################################################################
# How-to use
########################################################################################
# Run the make with as follow:
#
# ```bash
# make ${make_target} \
#      version_repo="X.Y.Z" \
#      tag_message = "the message your may want to associate with the Git tag" \
# ```

ifneq (,$(wildcard ./.envinit))
    include .envinit
    export
endif

ifneq (,$(wildcard ./.envdev))
    include .envdev
    export
endif

automatic = "N"
venv_command = "./venv/bin/activate"
version_repo = "0.0.0"
tag_message = ""

.SILENT:
.PHONY: clean testclean distclean coverageclean nuke

# Install project dependencies
install:
	uv sync

# Install development dependencies
install-dev:
	uv sync --dev

# Add a new dependency
add:
	uv add $(PACKAGE)

# Add a development dependency
add-dev:
	uv add --dev $(PACKAGE)

# Update dependencies
update:
	uv lock --upgrade
	uv sync

# Init
configure_repo_dev:
	python3 -m venv venv; \
	echo "${venv_command}"; \
	. $(venv_command); \
	pip3 list; \

	if [ ${automatic} = "N" ]; then \
		echo "Reply Y if and only if the pip3 list output above is consistent and does not display system packages !"; \
		echo "Ctrl+C to escape ..."; \
		go_to_install="N"; read -p "Do you want to install dependencies with pip ? (Y/N) " go_to_install; \
	if [ $$go_to_install = "Y" ]; then \
		. $(venv_command); \
		pip3 install -r requirements.txt -r requirements-dev.txt -e .; \
	else \
		echo "Reply was not Y, escape by an error."; \
		exit 1; \
	fi \
	fi

	. $(venv_command); \
	pre-commit install; \
	pre-commit autoupdate; \
	echo "Initial pre-commit run"; \
	pre-commit run --all-files; \
	echo "Virtual environment created, local repo configured with pre-commit hooks.";

# Development lifecycle
format_and_lint:
	. $(venv_command); \
	pre-commit run --all-files --verbose;

build:
	. $(venv_command); \
	python3 src/"${PACKAGENAME}"/app.py;

run:
	. $(venv_command); \
	export PYTHONPATH="${PYTHONPATH}:./src"; \
	uv run src/check_url.py "https://www.google.com";

test:
	. $(venv_command); \
	pytest --cov=src/"${PACKAGENAME}" -n auto -v --capture=no; \
	#coverage run -m pytest -v --capture=no; \
	#coverage report;

# Housekeeping
bump_version: VERSION
ifeq (${version_repo},"0.0.0")
	echo "Provide version_repo=X.Y.Z on CLI"
else
	git pull
	echo "Bumping repo to version ${version_repo}"
	echo ${version_repo} > VERSION
	sed -i "s/.*__version__.*/__version__ = \"${version_repo}\"/" "src/urlchecker/__init__.py"
	sed -i "s/.*version =.*/version = \"${version_repo}\"/" "pyproject.toml"
	git add VERSION
	git add "src/urlchecker/__init__.py"
	git add "pyproject.toml"
	git commit -m "BUMP to version ${version_repo}"
	git tag ${version_repo} -m "${tag_message}"
	git push
	git push --tags
endif

clean:
	-find . -name __pycache__ -print0 | xargs -0 rm -rf
	-find . -name "*.pyc" -print0 | xargs -0 rm -rf
	-find . -name "*.egg-info" -print0 | xargs -0 rm -rf

coverageclean:
	-rm src/urlchecker/.coverage
	-rm src/urlchecker/.coverage.*
	-rm src/urlchecker/coverage.xml
	-rm -rf src/urlchecker/htmlcov

distclean:
	-rm -rf ./dist
	-rm -rf ./build
	-rm -rf ./venv

migrate:
	echo "TODO";

nuke: clean distclean testclean

testclean: coverageclean clean
	-rm -rf .tox

# Makefile Doc
help :
	echo ""
	echo "\033[0;35m### I am your quick and dirty Help file :) ###\033[0;0m"
	echo ""
	echo "\033[0;34m# Run the make with the command as follow, with the arguments applicable to the wanted target:\033[0;0m"
	echo "make target \\"
	echo "     someparameter=\"somevalue\" \\"
	echo ""
	echo "Note: the arguments to be passed in to the make target command are depending on the wanted target."
	echo ""
	echo "\033[0;34m# Where target is part of the following list (with in brackets the argument hosts to be used):\033[0;0m"
	echo "\033[0;33m* Development Environment:\033[0;0m"
	echo "  * [none] configure_repo_dev (configure the local Python3 Virtual Environment and the pre-commit hooks)"
	echo "  * [none] run (run the Flask application with the Development server)"
	echo "  * [none] test (run the Flask Test Suite)"
	echo "  * [none] format_and_lint (format and lint the code out of a pre-commit, but using the exact same configuration)"
	echo "\033[0;33m* Housekeeping targets:\033[0;0m"
	echo "  * [none] bump_version (requires the definition of parameter version_repo=X.Y.Z on CLI, tag_message is also an optional facility to document a Git tag)"
	echo "  * clean"
	echo ""
	echo "\033[0;34m# Default arguments are:\033[0;0m"
	echo "* someparameter = \"somevalue\""
	echo ""
	echo "TODO"
