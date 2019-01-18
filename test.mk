# test.mk
# Part of ‘dput’, a Debian package upload toolkit.
#
# This is free software, and you are welcome to redistribute it under
# certain conditions; see the end of this file for copyright
# information, grant of license, and disclaimer of warranty.

# Makefile rules for test suite.

MODULE_DIR := $(CURDIR)

UNITTEST2 = /usr/bin/python3-unit2

export COVERAGE_DIR = ${MODULE_DIR}/.coverage
coverage_html_report_dir = ${MODULE_DIR}/htmlcov

TEST_MODULES += $(shell find ${MODULE_DIR}/ -name 'test_*.py')

MIGRATION_MODULE_GLOB = **/migrations/*.py

PYCODESTYLE_OPTS ?= --config $(CURDIR)/.pycodestyle.conf
pycodestyle_code_opts = ${PYCODESTYLE_OPTS} --exclude ${MIGRATION_MODULE_GLOB}
pycodestyle_migration_code_opts = ${PYCODESTYLE_OPTS} \
	--include ${MIGRATION_MODULE_GLOB} \
	--ignore E501

UNITTEST_NAMES ?=
UNITTEST_OPTS ?= ${UNITTEST_NAMES}

PYTHON_ISORT_OPTS ?= --check-only --diff


.PHONY: test
test: test-unittest

.PHONY: test-unittest
test-unittest:
	$(DJANGO_MANAGE) test ${UNITTEST_OPTS}

.PHONY: test-coverage
test-coverage: test-coverage-run test-coverage-html test-coverage-report

.PHONY: test-coverage-run
test-coverage-run: .coverage

.coverage: ${CODE_MODULES}
	$(PYTHON) -m coverage run --branch -m manage test ${UNITTEST_OPTS}

GENERATED_FILES += ${COVERAGE_DIR}

.PHONY: test-coverage-html
test-coverage-html: .coverage
	$(PYTHON) -m coverage html \
		--directory ${coverage_html_report_dir}/ \
		$(filter-out ${TEST_MODULES},${CODE_MODULES})

GENERATED_FILES += ${coverage_html_report_dir}

.PHONY: test-coverage-report
test-coverage-report: .coverage
	$(PYTHON) -m coverage report \
		$(filter-out ${TEST_MODULES},${CODE_MODULES})


.PHONY: test-static-analysis
test-static-analysis: test-python-isort test-pycodestyle

.PHONY: test-pycodestyle
test-pycodestyle:
	$(PYTHON) -m pycodestyle ${pycodestyle_code_opts} ${CODE_MODULE_GLOBS}
	if [ "${migration_code_modules}" ] ; then \
		$(PYTHON) -m pycodestyle ${pycodestyle_migration_code_opts} \
			${CODE_MODULE_GLOBS} ; \
	fi

.PHONY: test-python-isort
test-python-isort:
	$(PYTHON) -m isort ${PYTHON_ISORT_OPTS} ${CODE_MODULES}


# Copyright © 2008–2018 Ben Finney <bignose@debian.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.


# Local Variables:
# coding: utf-8
# mode: makefile
# End:
# vim: fileencoding=utf-8 filetype=make :
