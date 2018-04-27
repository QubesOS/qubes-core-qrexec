#!/usr/bin/python3 -O
# vim: fileencoding=utf-8

import os

import setuptools
import setuptools.command.install


# don't import: import * is unreliable and there is no need, since this is
# compile time and we have source files
def get_console_scripts():
    yield 'qrexec-policy', 'qrexec.tools.policy'
    yield 'qrexec-policy-agent', 'qrexec.tools.dbusagent'
    yield 'qrexec-policy-graph', 'qrexec.tools.graph'
    for filename in os.listdir('./qubes/tools'):
        basename, ext = os.path.splitext(os.path.basename(filename))
        if basename == '__init__' or ext != '.py':
            continue
        yield basename.replace('_', '-'), 'qubes.tools.{}'.format(basename)

# create simple scripts that run much faster than "console entry points"
class CustomInstall(setuptools.command.install.install):
    def run(self):
        bin = os.path.join(self.root, "usr/bin")
        try:
            os.makedirs(bin)
        except:
            pass
        for file, pkg in get_console_scripts():
           path = os.path.join(bin, file)
           with open(path, "w") as f:
               f.write(
"""#!/usr/bin/python3
from {} import main
import sys
if __name__ == '__main__':
	sys.exit(main())
""".format(pkg))

           os.chmod(path, 0o755)
        setuptools.command.install.install.run(self)

if __name__ == '__main__':
    setuptools.setup(
        name='qrexec',
        version=open('version').read().strip(),
        author='Invisible Things Lab',
        author_email='woju@invisiblethingslab.com',
        description='Qubes Qrexec package',
        license='GPL2+',
        url='https://www.qubes-os.org/',
        packages=setuptools.find_packages(exclude=('core*', 'tests')),
        package_data = {
            'qrexec': ['glade/*.glade'],
        },
        cmdclass={
            'install': CustomInstall,
        },
    )
