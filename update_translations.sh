#!/bin/bash
# Regenerate the translation template and merge it into all .po files.
# Only the GTK policy agent (ask dialog and notifications) is translated.
set -e
cd "$(dirname "$0")"

FILES="qrexec/tools/qrexec_policy_agent.py qrexec/glade/RPCConfirmationWindow.glade"

xgettext -d qubes-core-qrexec -o locale/qubes-core-qrexec.pot \
    --from-code=UTF-8 --add-comments=TRANSLATORS $FILES

find locale/* -maxdepth 2 -mindepth 2 -type f -iname 'qubes-core-qrexec.po' \
    -exec msgmerge --update --backup=none {} locale/qubes-core-qrexec.pot \;
