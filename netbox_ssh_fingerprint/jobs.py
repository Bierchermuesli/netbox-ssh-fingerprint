import uuid

from django.contrib.contenttypes.models import ContentType

from netbox.jobs import JobRunner
from utilities.request import NetBoxFakeRequest, apply_request_processors

from .scan import scan_host


def job_request(user):
    """
    A request stand-in so key changes made by the job land in the changelog under the job's user.
    """
    return NetBoxFakeRequest({
        'META': {}, 'COOKIES': {}, 'POST': {}, 'GET': {}, 'FILES': {},
        'user': user, 'method': 'POST', 'path': '', 'id': uuid.uuid4(),
    })


class FetchHostKeysJob(JobRunner):
    """
    Fetch the SSH host keys of one device or VM and compare them with the stored ones.
    """
    class Meta:
        name = 'Fetch SSH host keys'

    def run(self, object_type_id, object_id, *args, **kwargs):
        # Devices and VMs cannot own jobs in NetBox, so the host is passed as arguments
        host = ContentType.objects.get_for_id(object_type_id).get_object_for_this_type(pk=object_id)
        with apply_request_processors(job_request(self.job.user)):
            scan_host(host, logger=self.logger)

    @classmethod
    def enqueue_for(cls, host, user):
        ct = ContentType.objects.get_for_model(host)
        return cls.enqueue(user=user, name=f'Fetch SSH host keys: {host}', object_type_id=ct.pk, object_id=host.pk)
