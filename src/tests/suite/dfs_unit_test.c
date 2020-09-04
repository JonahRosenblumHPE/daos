/**
 * (C) Copyright 2019-2020 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */
#include "daos_iotest.h"
#include <pthread.h>
#include <daos_fs.h>

/** global DFS mount used for all tests */
static uuid_t           co_uuid;
static daos_handle_t    co_hdl;
static dfs_t		*dfs_mt;

static void
dfs_test_mount_umount(void **state)
{
	test_arg_t		*arg = *state;
	uuid_t			cuuid;
	daos_cont_info_t	co_info;
	daos_handle_t		coh;
	dfs_t			*dfs;
	int			rc;

	uuid_generate(cuuid);

	/** create a non-posix container */
	rc = daos_cont_create(arg->pool.poh, cuuid, NULL, NULL);
	assert_int_equal(rc, 0);
	print_message("Created non-POSIX Container "DF_UUIDF"\n",
		      DP_UUID(cuuid));

        /** open a non-posix container */
 	rc = daos_cont_open(arg->pool.poh, cuuid, DAOS_COO_RW,
			    &coh, &co_info, NULL);
	assert_int_equal(rc, 0);
        print_message("Opened non-POSIX Container \n");

	/** try to mount DFS on it, should fail. */
	rc = dfs_mount(arg->pool.poh, coh, O_RDWR, &dfs);
	assert_int_equal(rc, EINVAL);
        print_message("non-POSIX Container has not mounted\n");

        /** close a non-posix container */
	rc = daos_cont_close(coh, NULL);
	assert_int_equal(rc, 0);
        print_message("non-POSIX Container closed\n");

        /** destroy a non-posix container */
	rc = daos_cont_destroy(arg->pool.poh, cuuid, 1, NULL);
	assert_int_equal(rc, 0);
	print_message("Destroyed non-POSIX Container "DF_UUIDF"\n",
		      DP_UUID(cuuid));

	/** create & open the container with POSIX layout without mounting it */
	rc = dfs_cont_create(arg->pool.poh, cuuid, NULL, &coh, NULL);
	assert_int_equal(rc, 0);
	printf("Created and open DFS Container "DF_UUIDF"\n", DP_UUID(cuuid));

	/** RW mount for the container with POSIX layout */
	rc = dfs_mount(arg->pool.poh, coh, O_RDWR, &dfs);
	assert_int_equal(rc, 0);
	print_message("Mounting RW\n");

	/** Second mount without umount for the container with POSIX layout */
	rc = dfs_mount(arg->pool.poh, coh, O_RDWR, &dfs);
	assert_int_equal(rc, 0);
	print_message("Second mounting without umount\n");

	/** RW umount with POSIX layout */
	rc = dfs_umount(dfs);
	assert_int_equal(rc, 0);
	print_message("Unmounting RW\n");

	/** R mount for the container with POSIX layout */
	rc = dfs_mount(arg->pool.poh, coh, O_RDONLY, &dfs);
	assert_int_equal(rc, 0);
	print_message("Mounting readonly\n");

	/** R umount for the container with POSIX layout */
	rc = dfs_umount(dfs);
	assert_int_equal(rc, 0);
	print_message("Unmounting readonly\n");

	/** Wrong parameteres mount for the container with POSIX layout */
	rc = dfs_mount(arg->pool.poh, coh, -1, &dfs);
	assert_int_equal(rc, EINVAL);
	print_message("Mounting wrong parameters\n");

	/** NULL dfs mount */
	rc = dfs_mount(arg->pool.poh, coh, O_RDWR, /*&dfs*/ NULL);
	assert_int_equal(rc, EINVAL);
	print_message("Mounting NULL dfs\n");

	/** NULL dfs umount */
	rc = dfs_umount(/*dfs*/ NULL);
	assert_int_equal(rc, EINVAL);
	print_message("Unmount NULL dfs\n");

}

static void
dfs_test_open_release(void **state)
{
        dfs_obj_t               *obj;
        daos_size_t             chunk_size = 64;
        int                     rc;

	/** NULL dfs mount openning */
        rc = dfs_open(/*dfs_mt*/NULL, NULL, "test",
                      S_IFREG | S_IWUSR | S_IRUSR , O_RDWR | O_CREAT,
                      OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, EINVAL);
        print_message("Mounted file system should be provided\n");

	/** NULL file name openning */
        rc = dfs_open(dfs_mt, NULL, /*"test"*/ NULL,
                      S_IFREG | S_IWUSR | S_IRUSR , O_RDWR | O_CREAT,
                      OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, EINVAL);
        print_message("File name should be provided\n");

	/** No mode openning */
        rc = dfs_open(dfs_mt, NULL, "test",
                      /*S_IFREG | S_IWUSR | S_IRUSR*/ 0, O_RDWR | O_CREAT,
                      OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, EINVAL);
        print_message("mode_t (permissions + type) should be provided\n");

	/** Not existing file openning without creating */
        rc = dfs_open(dfs_mt, NULL, "test",
                      S_IFREG | S_IWUSR | S_IRUSR , /*O_RDWR | O_CREAT*/0,
                      OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, ENOENT);
        print_message("Not existing file can not be openn without creating\n");

	/** NULL object openning */
        rc = dfs_open(dfs_mt, NULL, "test",
                      S_IFREG | S_IWUSR | S_IRUSR , O_RDWR | O_CREAT,
                      OC_S1, chunk_size, NULL, /*&obj*/ NULL);
        assert_int_equal(rc, EINVAL);
        print_message("Open should get a pointer for an object\n");

	/** NULL object releasing */
        rc = dfs_release(/*obj*/NULL);
        assert_int_equal(rc, EINVAL);
        print_message("Release should get an object\n");

	/** Successful object creating for RW */
        rc = dfs_open(dfs_mt, NULL, "test", S_IFREG | S_IWUSR | S_IRUSR ,
                      O_RDWR | O_CREAT, OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, 0);
        print_message("Successfull object creating for RW\n");

        /** Successful object releasin */
        rc = dfs_release(obj);
        assert_int_equal(rc, 0);
        print_message("Successful object releasing\n");

        /** Successful object openning for RW */
        rc = dfs_open(dfs_mt, NULL, "test", S_IFREG | S_IWUSR | S_IRUSR ,
                      O_RDWR, OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, 0);
        print_message("Successfull object openning for RW\n");

        /** Successful object releasin */
        rc = dfs_release(obj);
        assert_int_equal(rc, 0);
        print_message("Successful object releasing\n");

        /** Successful object creating for RDONLY */
        rc = dfs_open(dfs_mt, NULL, "testR", S_IFREG | S_IWUSR | S_IRUSR ,
                      O_RDONLY | O_CREAT, OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, 0);
        print_message("Successfull object creating for RDONLY\n");

        /** Successful object releasin */
        rc = dfs_release(obj);
        assert_int_equal(rc, 0);
        print_message("Successful object releasing\n");

        /** Failure in object for RDONLY openning for RW */
        rc = dfs_open(dfs_mt, NULL, "testR", S_IFREG | S_IWUSR | S_IRUSR ,
                      O_RDWR, OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, /*EROFS*/ 0);
        print_message("Failed to open RDONLY object  for RW\n");

        /** Successful RDONLY object openning for RDONLY */
        rc = dfs_open(dfs_mt, NULL, "testR", S_IFREG | S_IWUSR | S_IRUSR ,
                      O_RDONLY, OC_S1, chunk_size, NULL, &obj);
        assert_int_equal(rc, 0);
        print_message("Successfull open RDONLY object for RDONLY\n");

        /** Successful object releasin */
        rc = dfs_release(obj);
        assert_int_equal(rc, 0);
        print_message("Successful object releasing\n");

}

static void
dfs_test_mkdir_remove(void **state)
{
        int rc;
 
	/** NULL dfs mount directory making */
	rc = dfs_mkdir(/*dfs_mt*/ NULL, NULL, "dir", S_IWUSR | S_IRUSR, 0);
        assert_int_equal(rc, EINVAL);
        print_message("Mounted file system should be provided for mkdir\n");

	/** NULL directory name making*/
	rc = dfs_mkdir(dfs_mt, NULL, /*"dir"*/ NULL, S_IWUSR | S_IRUSR, 0);
        assert_int_equal(rc, EINVAL);
	print_message("Directory name to create should be provided\n");

        /** The directory with permissions to do nothing may be created */
	rc = dfs_mkdir(dfs_mt, NULL, "dir",  0, 0);
        assert_int_equal(rc, 0);
        print_message("Permission for at least R or W is not checked\n");

        /** The directory with existing name can not be created */
	rc = dfs_mkdir(dfs_mt, NULL, "dir", S_IWUSR | S_IRUSR, 0);
        assert_int_equal(rc, EEXIST);
	print_message( "Another directory with existing name rejected\n");

	/** NULL directory name removing*/
        rc = dfs_remove(dfs_mt, NULL, /*"dir"*/ NULL, true, NULL);        
        assert_int_equal(rc, EINVAL);
        print_message("Directory name to remove should be provided\n");

	/** Successful directory removing */
        rc = dfs_remove(dfs_mt, NULL, "dir", true, NULL);        
	assert_int_equal(rc, 0);
	print_message("Successful rmdir\n");

	/** Not existing directory can not be removed */
        rc = dfs_remove(dfs_mt, NULL, "dir", true, NULL);        
	assert_int_equal(rc, ENOENT);
	print_message("Not existing directory can not be removed\n");

	/** NULL dfs mount directory removing */
        rc = dfs_remove(/*dfs_mt*/ NULL, NULL, "dir", true, NULL);        
	assert_int_equal(rc, EINVAL);
        print_message("Mounted file system should be provided for rmdir\n");
}

static void
dfs_test_query(void **state)
{
	dfs_attr_t         attr;
        int                rc;

	/** NULL dfs query */
 	rc = dfs_query(/*dfs_mt*/ NULL, &attr);
	assert_int_equal(rc, EINVAL);
	print_message("Query NULL dfs\n");

        /** NULL attrs for query */
	rc = dfs_query(dfs_mt, /*&attr*/ NULL);
	assert_int_equal(rc, EINVAL);
	print_message("Query with NULL attrs\n");

        /** Successful query */
 	rc = dfs_query(dfs_mt, &attr);
	assert_int_equal(rc, 0);
	print_message("Successful Query\n");
}

static void
dfs_test_global_local(void **state)
{
	d_iov_t            glob = { NULL, 0, 0 };
	dfs_t		  *dfs;
	daos_handle_t      poh;
        int                rc;

	/** NULL dfs mount for local */
	rc = dfs_local2global(/*dfs_mt*/ NULL, &glob);
	assert_int_equal(rc, EINVAL);
        print_message("Mounted file system should be provided as local\n");

	/** NULL for global result */
	rc = dfs_local2global(dfs_mt, /*&glob*/ NULL);
        assert_int_equal(rc, EINVAL);
        print_message("local2global should get a pointer for the global\n");

	/** Successful local2global length getting */
	rc = dfs_local2global(dfs_mt, &glob);
        assert_int_equal(rc, 0);
	print_message("Successful local2global length getting\n");

	/** NULL dfs mount for local result */
	rc = dfs_global2local(poh, co_hdl, O_RDWR, glob, /*&dfs*/ NULL);
        assert_int_equal(rc, EINVAL);
        print_message("global2local should get a pointer for the local\n");

	/** NULL iov_buf in glob */
	rc = dfs_global2local(poh, co_hdl, O_RDWR, glob, &dfs);
        assert_int_equal(rc, EINVAL);
	print_message("global2local should have buffer allocated for the resuly\n");

        /** allocate buffer for global pool handle */
        D_ALLOC(glob.iov_buf, glob.iov_buf_len);

        /** Buffer for glob should be big enough (it is still 0 size) */
        rc = dfs_global2local(poh, co_hdl, O_RDWR, glob, &dfs);
        assert_int_equal(rc, EINVAL);
        print_message("global2local should have buffer big enough for the result\n");

        glob.iov_len = glob.iov_buf_len;

        /** Local data should actualy come to global */
        rc = dfs_global2local(poh, co_hdl, /*O_RDWR*/ 0, glob, &dfs_mt);
        assert_int_equal(rc, EINVAL);
        print_message("global2locall failed because of magic\n");

	/** Successful local2global data getting */
	rc = dfs_local2global(dfs_mt, &glob);
        assert_int_equal(rc, 0);
	print_message("Successful local2global data getting\n");

        /** Successful global2local */
        rc = dfs_global2local(poh, co_hdl, /*O_RDWR*/ 0, glob, &dfs);
        assert_int_equal(rc, 0);
        print_message("Successful global2locall\n");

	if (rc != 0) return;

	/** local from global should be umont */
	rc = dfs_umount(dfs);
	assert_int_equal(rc, 0);
	print_message("Unmounting local from global\n");

}

static const struct CMUnitTest dfs_unit_tests[] = {
        { "DFS_UNIT_TEST1: DFS mount / umount / query",
          dfs_test_mount_umount, async_disable, test_case_teardown},
        { "DFS_UNIS TEST2: DFS open / release",
          dfs_test_open_release, async_disable, test_case_teardown},
	{ "DFS_UNIS TEST3: DFS mkdir / remove",
          dfs_test_mkdir_remove, async_disable, test_case_teardown},
        { "DFS_UNIS TEST4: DFS  query: ",
          dfs_test_query,        async_disable, test_case_teardown},
	{ "DFS_UNIS TEST5: Global / Local",
          dfs_test_global_local, async_disable, test_case_teardown},
};


static int
dfs_setup(void **state)
{
	test_arg_t              *arg;
	int                     rc = 0;

	rc = test_setup(state, SETUP_POOL_CONNECT, true, DEFAULT_POOL_SIZE,
			NULL);
	assert_int_equal(rc, 0);

	arg = *state;

	uuid_generate(co_uuid);
	rc = dfs_cont_create(arg->pool.poh, co_uuid, NULL, &co_hdl, &dfs_mt);
	assert_int_equal(rc, 0);
	printf("Created DFS Container "DF_UUIDF"\n", DP_UUID(co_uuid));

	return rc;

}

static int
dfs_teardown(void **state)
{
	test_arg_t      *arg = *state;
	int             rc;

	rc = dfs_umount(dfs_mt);
	assert_int_equal(rc, 0);
	rc = daos_cont_close(co_hdl, NULL);
	assert_int_equal(rc, 0);
	rc = daos_cont_destroy(arg->pool.poh, co_uuid, 1, NULL);
	assert_int_equal(rc, 0);
	printf("Destroyed DFS Container "DF_UUIDF"\n", DP_UUID(co_uuid));

	return test_teardown(state);
}


int
run_daos_fs_unit_test(int rank, int size, int *sub_tests, int sub_tests_size)
{
	int rc = 0;

	MPI_Barrier(MPI_COMM_WORLD);
	rc = cmocka_run_group_tests_name("DAOS FileSystem (DFS) unit tests",
					 dfs_unit_tests, dfs_setup,
					 dfs_teardown);
	MPI_Barrier(MPI_COMM_WORLD);
	return rc;
}
