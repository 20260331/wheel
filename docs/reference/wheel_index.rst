wheel index
===========

Usage
-----

::

    wheel index [-h] [--manifest PATH] [--lockfile PATH] [--project NAME]
                [--version VERSION] [--tag TAG] [--no-recursive]
                [--fail-on-conflict] DIRECTORY [...]

Description
-----------

Build a deterministic repository manifest and a lockfile from the wheel files
in one or more directories. Directories are scanned recursively by default.

The command works entirely offline: wheels are only read, never modified or
removed, and no network access is made. Running it twice against the same
directory produces byte-identical output.

Every indexed wheel is recorded with its normalized (PEP 503) project name and
normalized (PEP 440) version, all compatibility tags declared in its ``WHEEL``
metadata, file size, SHA-256 hash of the wheel file, a summary of its
``RECORD`` file (digest, number of recorded files and their total size), the
core metadata version (``Metadata-Version``) and its POSIX-style path relative
to the scanned directory. When several directories are given, paths are
prefixed with the corresponding directory name.

*Duplicate* candidates are byte-identical wheels (same hash) found at multiple
paths. *Conflicting* candidates share a project name and version but have
different content (different hashes). Both are listed in the manifest and the
lockfile and reported on standard error. Wheels that cannot be read (bad
filename, corrupt archive, invalid version) are listed under ``skipped``.

The lockfile selects one artifact per project: the highest available version,
breaking ties deterministically in favor of pure wheels, wheels with more
compatibility tags, and finally the lexicographically first tag set and path.
Selections made in the presence of conflicts are marked with
``"conflicting": true`` and list the unchosen paths under ``alternates``.

Options
-------

.. option:: --manifest=PATH

    Write the repository manifest to this path (default:
    ``wheel-manifest.json``).

.. option:: --lockfile=PATH

    Write the lockfile to this path (default: ``wheel-lock.json``).

.. option:: --project=NAME

    Include only wheels of this project. The name is normalized according to
    PEP 503, so ``--project My_Pkg`` matches ``my-pkg``. May be given multiple
    times.

.. option:: --version=VERSION

    Include only wheels matching this exact version (``1.0``) or PEP 440
    version specifier (``>=1.0,<2``). May be given multiple times; a wheel is
    included if it matches any of the given values.

.. option:: --tag=TAG

    Include only wheels that provide at least one of the given compatibility
    tags, such as ``py3-none-any``. May be given multiple times.

.. option:: --no-recursive

    Scan only the given directories without descending into subdirectories.

.. option:: --fail-on-conflict

    Exit with a non-zero status if conflicting candidates are found.

Examples
--------

* Index every wheel below ``./wheelhouse`` into the default files::

    $ wheel index ./wheelhouse

* Index only Python 3 pure-Python wheels from two directories::

    $ wheel index ./wheelhouse ./extra --tag py3-none-any

* Fail a CI job when the same project/version exists with different contents::

    $ wheel index ./wheelhouse --fail-on-conflict
