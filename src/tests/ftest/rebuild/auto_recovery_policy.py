"""
  (C) Copyright 2025 Hewlett Packard Enterprise Development LP

  SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from ior_test_base import IorTestBase


class RbldAutoRecoveryPolicy(IorTestBase):
    # pylint: disable=too-few-public-methods
    """Rebuild test cases featuring IOR.

    This class contains tests for pool rebuild that feature I/O going on
    during the rebuild using IOR.

    :avocado: recursive
    """

    def test_rebuild_auto_recovery_policy(self):
        """Jira ID: DAOS-17420.

        Test Description: Verify Rebuild Auto Recovery Policy

        :avocado: tags=all,full_regression
        :avocado: tags=hw,medium
        :avocado: tags=pool,rebuild
        :avocado: tags=RbldAutoRecoveryPolicy,test_rebuild_auto_recovery_policy
        """
        self.log_step('Setup pool')
        # pool = self.get_pool()
        dmg = self.get_dmg_command()

        # TODO create sanity container with small amount of data
        # TODO is this necessary?

        # Get two different ranks to exclude
        all_ranks = list(self.server_managers[0].ranks.keys())
        ranks_x = self.random.sample(all_ranks, k=1)
        ranks_y = self.ranom.sample(list(set(all_ranks) - set(ranks_x)))

        self.log_step('Verify dmg system stop with auto recovery disabled')
        # TODO disable auto recovery
        dmg.system_stop(ranks=ranks_x)
        # TODO verify no exclusions and no rebuild starts
        #      how long to wait? Maybe some multiple of SWIM timeout, etc?

        self.log_step('Verify enabling auto recovery starts rebuild')
        # TODO enable auto recovery
        # TODO verify rank X excluded
        # TODO verify rank X rebuilt in pool
        dmg.system_stop(ranks=ranks_y)
        # TODO verify rank Y excluded
        # TODO verify rank Y rebuilt in pool

        self.log_step('Restore system to a healthy state')
        # We can either start from scratch or we can reintegrate the ranks to continue.
        # If we reintegrate the ranks, it's more like a production system
        dmg.system_start(ranks=ranks_x + ranks_y)
        dmg.system_reintegrate(ranks=ranks_x + ranks_y)
        # TODO wait for rebuild to complete

        self.log_step('Verify system.pool_rebuild=no')
        # TODO enable auto recovery
        # TODO set system.pool_rebuild = no
        dmg.system_stop(ranks=ranks_x)
        # TODO verify X is excluded but rebuild did not start
        dmg.system_start(ranks=ranks_x)
        # TODO verify X no longer excluded from the system
        dmg.system_reintegrate(ranks=ranks_x)
        # TODO verify X no longer excluded from the pool
        # TODO X rebuilt in the pool
        # TODO set system.pool_rebuild = no
        # TODO verify no further rebuild
        # TODO restore system.pool_rebuild = yes

        self.log_step('Verify stopping more ranks than the RF does not trigger rebuild')
        # TODO disable auto recovery
        rf = 2  # TODO dynamic
        ranks_stop = self.random.sample(all_ranks, k=rf)
        dmg.system_stop(ranks=ranks_stop)
        # TODO verify no exclusions and no rebuild starts
        dmg.system_start(ranks=ranks_x)
        # TODO enable auto recovery
        # TODO verify no further rebuild or exclusions

        self.log_step('Verify stopping all ranks does not trigger rebuild')
        # TODO disable auto recovery
        dmg.system_stop()
        # TODO verify no exclusions and no rebuild starts
        dmg.system_start()
        # TODO enable auto recovery
        # TODO verify no further rebuild or exclusions

        self.log_step('Verify policy can be modified before exclusions occur')
        # TODO enable auto recovery
        # Stop all ranks except 1
        ranks_stop = self.random.sample(all_ranks, k=len(all_ranks) - 1)
        dmg.system_stop(ranks=ranks_stop)
        # TODO immediately disable auto recovery
        # TODO verify no exclusions and no rebuild starts
        dmg.system_start()
        # TODO verify no further rebuild or exclusions

        self.log_step('Verify with multiple pools')
        # TODO wiki is unsure whether pool-granularity is needed
