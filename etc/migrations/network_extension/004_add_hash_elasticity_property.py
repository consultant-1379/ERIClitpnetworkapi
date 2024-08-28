from litp.migration import BaseMigration
from litp.migration.operations import AddProperty


class Migration(BaseMigration):
    version = '1.33.1'
    operations = [
        AddProperty('bridge', 'hash_elasticity', '4'),
    ]
