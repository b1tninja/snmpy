# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation of
# finding any built-in configuration documentation, at
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, you can omit it.

sys.path.insert(0, os.path.abspath(".."))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "snmpy"
copyright = "2026, snmpy Contributors"
author = "snmpy Contributors"
release = "1.0.0"
# For release, you can also set a version number if you have one.
# For example, if your project has a "1.0.0" version, you would set:
# release = "1.0.0"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_rtd_theme",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# The suffix(es) of source filenames.
source_suffix = ".rst"

# The master toctree document.
master_doc = "index"

# intersphinx configuration (optional, for linking to Python docs)
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

# Theme options
html_theme_options = {
    "style_external_links": True,
    "collapse_navigation": False,
}

# -- Options for autodoc -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html

# Automatically generate Stub files
autosummary_generate = True

# Document only public members
autodoc_default_flags = [
    "members",
    "undoc-members",
    "private-members",
    "show-inheritance",
]

# Sort members by source order
autodoc_member_order = "bysource"

# Keep type hints in documentation
autodoc_typehints = "signature"
autodoc_typehints_description_target = "documented"

