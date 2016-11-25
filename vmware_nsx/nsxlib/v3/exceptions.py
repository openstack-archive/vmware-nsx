# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from oslo_utils import excutils
import six

from vmware_nsx._i18n import _


class NsxLibException(Exception):
    """Base NsxLib Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = _("An unknown exception occurred.")

    def __init__(self, **kwargs):
        try:
            super(NsxLibException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(NsxLibException, self).__init__(self.message)

    if six.PY2:
        def __unicode__(self):
            return unicode(self.msg)

    def __str__(self):
        return self.msg

    def use_fatal_exceptions(self):
        return False


class ManagerError(NsxLibException):
    message = _("Unexpected error from backend manager (%(manager)s) "
                "for %(operation)s %(details)s")

    def __init__(self, **kwargs):
        details = kwargs.get('details', '')
        kwargs['details'] = ': %s' % details
        super(ManagerError, self).__init__(**kwargs)
        try:
            self.msg = self.message % kwargs
        except KeyError:
            self.msg = details


class ResourceNotFound(ManagerError):
    message = _("Resource could not be found on backend (%(manager)s) for "
                "%(operation)s")


class StaleRevision(ManagerError):
    pass


class ServiceClusterUnavailable(ManagerError):
    message = _("Service cluster: '%(cluster_id)s' is unavailable. Please, "
                "check NSX setup and/or configuration")


class NSGroupMemberNotFound(ManagerError):
    message = _("Could not find NSGroup %(nsgroup_id)s member %(member_id)s "
                "for removal.")


class NSGroupIsFull(ManagerError):
    message = _("NSGroup %(nsgroup_id)s contains has reached its maximum "
                "capacity, unable to add additional members.")


class NumberOfNsgroupCriteriaTagsReached(ManagerError):
    message = _("Port can be associated with at most %(max_num)s "
                "security-groups.")


class SecurityGroupMaximumCapacityReached(ManagerError):
    message = _("Security Group %(sg_id)s has reached its maximum capacity, "
                "no more ports can be associated with this security-group.")
