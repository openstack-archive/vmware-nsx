# Copyright 2017 VMware, Inc.
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

import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from oslo_config import cfg
from oslo_log import log
import stevedore

from neutron_lib import exceptions as n_exc
from vmware_nsx.common import locking

LOG = log.getLogger(__name__)
ALL_DUMMY_JOB = {
    'name': 'all',
    'description': 'Execute all housekeepers',
    'enabled': True,
    'error_count': 0,
    'fixed_count': 0,
    'error_info': None}


class NsxvHousekeeper(stevedore.named.NamedExtensionManager):
    def __init__(self, hk_ns, hk_jobs):
        self.email_notifier = None
        if (cfg.CONF.smtp_gateway and
                cfg.CONF.smtp_from_addr and
                cfg.CONF.snmp_to_list):
            self.email_notifier = HousekeeperEmailNotifier()

        self.readonly = cfg.CONF.nsxv.housekeeping_readonly
        self.results = {}

        if self.readonly:
            LOG.info('Housekeeper initialized in readonly mode')
        else:
            LOG.info('Housekeeper initialized')

        self.jobs = {}
        super(NsxvHousekeeper, self).__init__(
            hk_ns, hk_jobs, invoke_on_load=True, invoke_args=(self.readonly,))

        LOG.info("Loaded housekeeping job names: %s", self.names())
        for job in self:
            if job.obj.get_name() in cfg.CONF.nsxv.housekeeping_jobs:
                self.jobs[job.obj.get_name()] = job.obj

    def get(self, job_name):
        if job_name == ALL_DUMMY_JOB['name']:
            return {'name': job_name,
                    'description': ALL_DUMMY_JOB['description'],
                    'enabled': job_name in self.jobs,
                    'error_count': self.results.get(
                        job_name, {}).get('error_count', 0),
                    'fixed_count': self.results.get(
                        job_name, {}).get('fixed_count', 0),
                    'error_info': self.results.get(
                        job_name, {}).get('error_info', '')}

        for job in self:
            name = job.obj.get_name()
            if job_name == name:
                return {'name': job_name,
                        'description': job.obj.get_description(),
                        'enabled': job_name in self.jobs,
                        'error_count': self.results.get(
                            job_name, {}).get('error_count', 0),
                        'fixed_count': self.results.get(
                            job_name, {}).get('fixed_count', 0),
                        'error_info': self.results.get(
                            job_name, {}).get('error_info', '')}

        raise n_exc.ObjectNotFound(id=job_name)

    def list(self):
        results = [{'name': ALL_DUMMY_JOB['name'],
                    'description': ALL_DUMMY_JOB['description'],
                    'enabled': ALL_DUMMY_JOB['name'] in self.jobs,
                    'error_count': self.results.get(
                        ALL_DUMMY_JOB['name'], {}).get('error_count', 0),
                    'fixed_count': self.results.get(
                        ALL_DUMMY_JOB['name'], {}).get('fixed_count', 0),
                    'error_info': self.results.get(
                        ALL_DUMMY_JOB['name'], {}).get('error_info', '')}]

        for job in self:
            job_name = job.obj.get_name()
            results.append({'name': job_name,
                            'description': job.obj.get_description(),
                            'enabled': job_name in self.jobs,
                            'error_count': self.results.get(
                                job_name, {}).get('error_count', 0),
                            'fixed_count': self.results.get(
                                job_name, {}).get('fixed_count', 0),
                            'error_info': self.results.get(
                                job_name, {}).get('error_info', '')})

        return results

    def run(self, context, job_name):
        self.results = {}
        if context.is_admin:
            if self.email_notifier:
                self.email_notifier.start('Cloud Housekeeper Execution Report')

            with locking.LockManager.get_lock('nsx-housekeeper'):
                error_count = 0
                fixed_count = 0
                error_info = ''
                if job_name == ALL_DUMMY_JOB.get('name'):
                    for job in self.jobs.values():
                        result = job.run(context)
                        if result:
                            if self.email_notifier and result['error_count']:
                                self._add_job_text_to_notifier(job, result)
                            error_count += result['error_count']
                            fixed_count += result['fixed_count']
                            error_info += result['error_info'] + "\n"
                    self.results[job_name] = {
                        'error_count': error_count,
                        'fixed_count': fixed_count,
                        'error_info': error_info
                    }

                else:
                    job = self.jobs.get(job_name)
                    if job:
                        result = job.run(context)
                        if result:
                            error_count = result['error_count']
                            if self.email_notifier:
                                self._add_job_text_to_notifier(job, result)
                            self.results[job.get_name()] = result
                    else:
                        raise n_exc.ObjectNotFound(id=job_name)

                if self.email_notifier and error_count:
                    self.email_notifier.send()
        else:
            raise n_exc.AdminRequired()

    def _add_job_text_to_notifier(self, job, result):
        self.email_notifier.add_text("<b>%s:</b>", job.get_name())
        self.email_notifier.add_text(
            '%d errors found, %d fixed\n%s\n\n',
            result['error_count'],
            result['fixed_count'],
            result['error_info'])


class HousekeeperEmailNotifier(object):
    def __init__(self):
        self.msg = None
        self.html = None
        self.has_text = False

    def start(self, subject):
        self.msg = MIMEMultipart('alternative')
        self.msg['Subject'] = subject
        self.msg['From'] = cfg.CONF.smtp_from_addr
        self.msg['To'] = ', '.join(cfg.CONF.snmp_to_list)
        self.html = '<html><div>'
        self.has_text = False

    def add_text(self, fmt, *args):
        self.has_text = True
        text = fmt % args
        LOG.debug("Housekeeper emailer adding text %s", text)
        self.html += text.replace("\n", "<br>") + "<br>\n"

    def send(self):
        if self.has_text:
            self.html += "</div></html>"
            part1 = MIMEText(self.html, 'html')
            self.msg.attach(part1)

            s = smtplib.SMTP(cfg.CONF.smtp_gateway)

            s.sendmail(cfg.CONF.smtp_from_addr,
                       cfg.CONF.snmp_to_list,
                       self.msg.as_string())
            s.quit()

        self.msg = None
        self.html = None
