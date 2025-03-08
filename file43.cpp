/*
	This file is part of soltest.

	soltest is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	soltest is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with soltest.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file main.cpp
 * @author Alexander Arlt <alexander.arlt@arlt-labs.com>
 * @date 2018
 * Stub for generating main boost.test module.
 * based on solidity/test/boostTest.cpp written by Marko Simovic <markobarko@gmail.com>
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4535) // calling _set_se_translator requires /EHa
#endif

#include <boost/test/included/unit_test.hpp>
#include <boost/test/utils/runtime/cla/parser.hpp>

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#pragma GCC diagnostic pop

using namespace boost::unit_test;

#include <libsoltesting/Soltest.h>
#include <soltest/BuildInfo.h>
#include <soltest/TestSuiteGenerator.h>

#include <iostream>
#include <Poco/ThreadPool.h>

static soltest::Soltest* g_soltest;
static soltest::TestSuiteGenerator* g_testSuiteGenerator;

#ifdef BOOST_TEST_ALTERNATIVE_INIT_API

bool soltest_init_unit_test_suite()
#else
test_suite *soltest_init_unit_test_suite(int argc, char **argv)
#endif
{
	master_test_suite_t& master = framework::master_test_suite();
	master.p_name.value = "soltest";

	static soltest::TestSuiteGenerator testSuiteGenerator(*g_soltest, master);
	g_testSuiteGenerator = &testSuiteGenerator;

	// todo: add warning-as-error option
	testSuiteGenerator.load(false);

#ifdef BOOST_TEST_ALTERNATIVE_INIT_API
	return true;
#else
	return nullptr;
#endif
}

struct TestcaseCounter: public boost::unit_test::test_tree_visitor
{
	TestcaseCounter() : count(0)
	{
	}

	std::size_t count;

	bool visit(test_unit const& unit) override
	{
		++count;
		return test_tree_visitor::visit(unit);
	}
};

void ParseCommandLineArguments(soltest::Soltest& soltest, int argc, char** argv)
{
	unsigned int threads;
	unsigned int solidityThreads;
	std::string ipcPath;
	for (auto i = 0; i < argc; i++)
	{
		std::string argument(argv[i]);
		std::string absolutePath(argument);
		if (!boost::filesystem::path(argument).is_absolute())
			absolutePath =
				boost::filesystem::current_path().string() + boost::filesystem::path::preferred_separator + argument;
		if (argument == "--ipcpath")
		{
			ipcPath = argv[i + 1];
			++i;
		}
		else if (argument == "--solidity-threads")
		{
			try
			{
				solidityThreads = boost::lexical_cast<unsigned int>(argv[i + 1]);
				if (solidityThreads > 64)
					solidityThreads = std::thread::hardware_concurrency();
			}
			catch (...)
			{
				solidityThreads = 1;
			}
			if (solidityThreads == 0)
				solidityThreads = 1;
			soltest.setSolidityThreads(solidityThreads);
			++i;
		}
		else if (argument == "--threads")
		{
			try
			{
				threads = boost::lexical_cast<unsigned int>(argv[i + 1]);
				if (threads > 64)
					threads = std::thread::hardware_concurrency();
			}
			catch (...)
			{
				threads = 1;
			}
			if (threads == 0)
				threads = 1;
			soltest.setThreads(threads);
			++i;
		}
		else if (boost::filesystem::exists(absolutePath))
			if (boost::filesystem::extension(absolutePath) == ".abi")
				soltest.addAbiFile(absolutePath);
		if (boost::filesystem::extension(absolutePath) == ".sol")
			soltest.addSolidityFile(absolutePath);
		else if (boost::filesystem::extension(absolutePath) == ".soltest")
		{
			std::string contractFile(absolutePath.substr(0, absolutePath.length() - 4));
			soltest.addSoltestFile(absolutePath);
			if (boost::filesystem::exists(contractFile))
				soltest.addSolidityFile(contractFile);
		}
	}
}

int main(int argc, char* argv[])
{
	std::cout << "soltest v" << ETH_PROJECT_VERSION << std::endl;
	std::cout << "By Alexander Arlt <alexander.arlt@arlt-labs.com>, 2018." << std::endl << std::endl;

	std::cout << "Loading test cases..." << std::flush;

	static soltest::Soltest soltest;
	g_soltest = &soltest;

	ParseCommandLineArguments(*g_soltest, argc, argv);

	if (!soltest.load())
	{
		std::cout << "\rLoading test cases... error" << std::endl;
		std::map<std::string, soltest::Testcases::Ptr> testcases = g_soltest->testcases();
		for (auto& testcase : testcases)
		{
			std::vector<soltest::Testcases::Error::Ptr> const& errors = testcase.second->errors();
			for (auto& error : errors)
				std::cerr << error->what << std::endl << std::endl;
		}
		return boost::exit_failure;
	}
	std::cout << "\rLoading test cases... done" << std::endl;

	int result_code = 0;

	BOOST_TEST_I_TRY
	{
		framework::init(soltest_init_unit_test_suite, argc, argv);

		framework::finalize_setup_phase();

		if (!g_testSuiteGenerator->error())
		{
			TestcaseCounter counter;
			traverse_test_tree(boost::unit_test::framework::master_test_suite().p_id, counter, true);

			std::cout << "Preparing " << counter.count - 1 << " test cases..." << std::flush;
			std::cout << "\rPreparing " << counter.count - 1 << " test cases... done" << std::endl;

			std::cout << "Running " << counter.count - 1 << " test cases using "
					  << g_soltest->threads() << " threads..." << std::flush;
			g_testSuiteGenerator->runTestcases();

			std::cout << "\rRunning " << counter.count - 1 << " test cases using "
					  << g_soltest->threads() << " threads... done" << std::endl;

			std::cout << "Processing results..." << std::endl;

			framework::run();

			std::cout << "Processing results... done" << std::endl;
		}
		else
			return boost::exit_failure;

		results_reporter::make_report();

		result_code = results_collector.results(framework::master_test_suite().p_id).result_code();
	}
	BOOST_TEST_I_CATCH(framework::nothing_to_test, ex)
	{
		result_code = ex.m_result_code;
	}
	BOOST_TEST_I_CATCH(framework::internal_error, ex)
	{
		results_reporter::get_stream() << "Boost.Test framework internal error: " << ex.what() << std::endl;

		result_code = boost::exit_exception_failure;
	}
	BOOST_TEST_I_CATCH(framework::setup_error, ex)
	{
		results_reporter::get_stream() << "Test setup error: " << ex.what() << std::endl;

		result_code = boost::exit_exception_failure;
	}
	BOOST_TEST_I_CATCHALL()
	{
		results_reporter::get_stream() << "Boost.Test framework internal error: unknown reason" << std::endl;

		result_code = boost::exit_exception_failure;
	}

	framework::shutdown();

	return result_code;
}
