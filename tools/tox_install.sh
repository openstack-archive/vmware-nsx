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

ZUUL_CLONER=/usr/zuul-env/bin/zuul-cloner
BRANCH_NAME=stable/mitaka
neutron_installed=$(echo "import neutron" | python 2>/dev/null ; echo $?)
networking_l2gw_installed=$(echo "import networking_l2gw" | python 2>/dev/null ; echo $?)
neutron_lbaas_installed=$(echo "import neutron_lbaas" | python 2>/dev/null ; echo $?)

set -ex

cwd=$(/bin/pwd)
> /tmp/tox_install.txt

zuul_cloner () {
    echo "ZUUL CLONER" >> /tmp/tox_install.txt
    cd /tmp
    $ZUUL_CLONER --cache-dir \
        /opt/git \
        --branch $BRANCH_NAME \
        git://git.openstack.org $1
    cd $1
    pip install -e .
    cd "$cwd"
}

pip_hardcode () {
    echo "PIP HARDCODE: $1" >> /tmp/tox_install.txt
    pip install -chttps://git.openstack.org/cgit/openstack/requirements/plain/upper-constraints.txt?h=$BRANCH_NAME -U -egit+https://git.openstack.org/openstack/$1@$BRANCH_NAME#egg=$1
}

if [ $neutron_installed -eq 0 ]; then
    echo "NEUTRON ALREADY INSTALLED" >> /tmp/tox_install.txt
    echo "Neutron already installed; using existing package"
elif [ -x "$ZUUL_CLONER" ]; then
    zuul_cloner openstack/neutron
else
    pip_hardcode neutron
fi

if [ $networking_l2gw_installed -eq 0 ]; then
    echo "NETWORKING_L2GW ALREADY INSTALLED" >> /tmp/tox_install.txt
    echo "Networking-l2gw already installed; using existing package"
elif [ -x "$ZUUL_CLONER" ]; then
    zuul_cloner openstack/networking-l2gw
else
    pip_hardcode networking-l2gw
fi

if [ $neutron_lbaas_installed -eq 0 ]; then
    echo "NEUTRON_LBAAS ALREADY INSTALLED" >> /tmp/tox_install.txt
    echo "Neutron_lbaas already installed; using existing package"
elif [ -x "$ZUUL_CLONER" ]; then
    zuul_cloner openstack/neutron-lbaas
else
    pip_hardcode neutron-lbaas
fi

pip install -U $*
exit $?
