from litp.migration import BaseMigration
from litp.migration.operations import RemoveProperty

class Migration(BaseMigration):
    version = '1.23.5'
    operations = [
        RemoveProperty('vip', 'device_name'),
    ]
