from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.25.1'
    operations = [
        AddProperty('bridge', 'multicast_snooping', '1'),
    ]
