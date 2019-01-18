#! /usr/bin/make -f
#
# This is free software, and you are welcome to redistribute it under
# certain conditions; see the end of this file for copyright
# information, grant of license, and disclaimer of warranty.

# Makefile for ‘dput’ code base.

PYTHON ?= /usr/bin/python3
PYTHON_OPTS ?= -bb

UNITTEST2 = /usr/bin/python3-unit2

PY_MODULE_SUFFIX = .py
PY_MODULE_BYTECODE_SUFFIX = .pyc
package_modules = $(shell find ${CURDIR}/dput/ -name '*${PY_MODULE_SUFFIX}')
python_modules = $(shell find ${CURDIR}/ -name '*${PY_MODULE_SUFFIX}')

GENERATED_FILES :=
GENERATED_FILES += $(patsubst \
	%${PY_MODULE_SUFFIX},%${PY_MODULE_BYTECODE_SUFFIX}, \
	${python_modules})
GENERATED_FILES += ${CURDIR}/*.egg-info
GENERATED_FILES += ${CURDIR}/build ${CURDIR}/dist

DOC_DIR = doc
MANPAGE_GLOB = *.[1-8]
MANPAGE_DIR = ${DOC_DIR}/man
manpage_paths = $(wildcard ${MANPAGE_DIR}/${MANPAGE_GLOB})

UNITTEST_NAMES ?= discover
UNITTEST_OPTS ?= ${UNITTEST_NAMES} --buffer

PYTHON_COVERAGE = $(PYTHON) ${PYTHON_OPTS} -m coverage
COVERAGE_RUN_OPTS ?= --branch
COVERAGE_REPORT_OPTS ?=
COVERAGE_TEXT_REPORT_OPTS ?=
COVERAGE_HTML_REPORT_OPTS ?=


.PHONY: all
all:


.PHONY: clean
clean:
	$(RM) -r ${GENERATED_FILES}


.PHONY: tags
tags: TAGS

GENERATED_FILES += TAGS

TAGS: ${python_modules}
	etags --output "$@" --lang=python ${python_modules}


.PHONY: test
test: test-unittest test-manpages

.PHONY: test-unittest
test-unittest:
	$(PYTHON) ${PYTHON_OPTS} -m unittest ${UNITTEST_OPTS}

.PHONY: test-coverage
test-coverage: test-coverage-run test-coverage-html test-coverage-report

GENERATED_FILES += .coverage

.PHONY: test-coverage-run
test-coverage-run: coverage_opts = ${COVERAGE_RUN_OPTS}
test-coverage-run:
	$(PYTHON) ${PYTHON_OPTS} -m coverage run ${coverage_opts} \
		-m unittest ${UNITTEST_OPTS}

GENERATED_FILES += htmlcov/

.PHONY: test-coverage-html
test-coverage-html: coverage_opts = ${COVERAGE_REPORT_OPTS} ${COVERAGE_HTML_REPORT_OPTS}
test-coverage-html:
	$(PYTHON_COVERAGE) html ${coverage_opts} ${package_modules}

.PHONY: test-coverage-report
test-coverage-report: coverage_opts = ${COVERAGE_REPORT_OPTS} ${COVERAGE_TEXT_REPORT_OPTS}
test-coverage-report:
	$(PYTHON_COVERAGE) report ${coverage_opts} ${package_modules}

.PHONY: test-manpages
test-manpages: export LC_ALL = C.UTF-8
test-manpages: export MANROFFSEQ =
test-manpages: export MANWIDTH = 80
test-manpages: export MANOPTS = --encoding=UTF-8 --troff-device=utf8 --ditroff
test-manpages: ${manpage_paths}
	for manfile in $^ ; do \
		printf "Rendering %s:" $$manfile ; \
		man --local-file --warnings $$manfile > /dev/null ; \
		printf " done.\n" ; \
	done


.PHONY: stylecheck
stylecheck: stylecheck-pycodestyle

.PHONY: stylecheck-pycodestyle
stylecheck-pycodestyle:
	$(PYTHON) ${PYTHON_OPTS} -m pycodestyle ${python_modules}

.PHONY: stylecheck-pydocstyle
stylecheck-pydocstyle:
	$(PYTHON) ${PYTHON_OPTS} -m pydocstyle ${python_modules}

.PHONY: stylecheck-pylint
stylecheck-pylint:
	$(PYTHON) ${PYTHON_OPTS} -m pylint ${python_modules}


# Copyright © 2015–2018 Ben Finney <bignose@debian.org>
#
# This is free software: you may copy, modify, and/or distribute this work
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; version 3 of that license or any later version.
# No warranty expressed or implied. See the file ‘LICENSE.GPL-3’ for details.


# Local variables:
# coding: utf-8
# mode: makefile
# End:
# vim: fileencoding=utf-8 filetype=make :
