import pytest
from contextlib import ExitStack
from util import unique_name, config_value_context, new_test_keyspace
from cassandra.protocol import InvalidRequest


# Tests for ALTERing KS which uses tablets underneath. Because tablets
# feature does not exist in Cassandra , *all* tests in this file are
# Scylla-only. Let's mark them all scylla_only with an autouse fixture:
@pytest.fixture(scope="function", autouse=True)
def all_tests_are_scylla_only(scylla_only):
    pass


def test_given_existing_ks_when_altering_its_rf_by_more_than_one_should_fail_the_query(cql, this_dc):
    with new_test_keyspace(cql, " WITH replication = {'class': 'NetworkTopologyStrategy', "
                                "'replication_factor': 3, 'initial_tablets': 8};") as ks:
        # with pytest.raises(InvalidRequest):
        cql.execute_async("ALTER KEYSPACE " + ks + " WITH replication"
                          " = {'class': 'NetworkTopologyStrategy', 'replication_factor': 5}; ")