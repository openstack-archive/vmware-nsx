#!/bin/sh

# Many of neutron's repos suffer from the problem of depending on neutron,
# but it not existing on pypi.

# This wrapper for tox's package installer will use the existing package
# if it exists, else use zuul-cloner if that program exists, else grab it
# from neutron master via a hard-coded URL. That last case should only
# happen with devs running unit tests locally.

# From the tox.ini config page:
# install_command=ARGV
# default:
# pip install {opts} {packages}

PROJ=$1
MOD=$2
shift 2

ZUUL_CLONER=/usr/zuul-env/bin/zuul-cloner
neutron_installed=$(echo "import ${MOD}" | python 2>/dev/null ; echo $?)
BRANCH_NAME=stable/pike
PROJ_DIR=${HOME}/src/git.openstack.org/openstack/${PROJ}

set -e

CONSTRAINTS_FILE=$1
shift

install_cmd="pip install"
if [ $CONSTRAINTS_FILE != "unconstrained" ]; then
    install_cmd="$install_cmd -c$CONSTRAINTS_FILE"
fi

if [ -d "$PROJ_DIR" ]; then
    echo "FOUND code at $PROJ_DIR - using"
    $install_cmd -U -e ${PROJ_DIR}
elif [ $neutron_installed -eq 0 ]; then
    echo "ALREADY INSTALLED" > /tmp/tox_install-${PROJ}.txt
    echo "${PROJ} already installed; using existing package"
elif [ -x "$ZUUL_CLONER" ]; then
    echo "${PROJ} not installed; using zuul cloner"
    echo "ZUUL CLONER" > /tmp/tox_install-${PROJ}.txt
    cwd=$(/bin/pwd)
    cd /tmp
    $ZUUL_CLONER --cache-dir \
        /opt/git \
        --branch ${BRANCH_NAME} \
        https://git.openstack.org \
        openstack/${PROJ}
    cd openstack/${PROJ}
    $install_cmd -e .
    cd "$cwd"
else
    echo "${PROJ} not installed; using egg"
    echo "PIP HARDCODE" > /tmp/tox_install-${PROJ}.txt
    $install_cmd -U -egit+https://git.openstack.org/openstack/${PROJ}@${BRANCH_NAME}#egg=${PROJ}
fi
