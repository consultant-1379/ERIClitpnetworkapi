from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.23.2'
    operations = [
        AddProperty('vip', 'device_name'),
    ]
