.. contents:: **allpairspy** forked from `bayandin/allpairs <https://github.com/bayandin/allpairs>`__
   :backlinks: top
   :depth: 2

.. image:: https://badge.fury.io/py/allpairspy.svg
    :target: https://badge.fury.io/py/allpairspy
    :alt: PyPI package version

.. image:: https://img.shields.io/pypi/pyversions/allpairspy.svg
    :target: https://pypi.org/project/allpairspy
    :alt: Supported Python versions

.. image:: https://github.com/thombashi/allpairspy/workflows/Tests/badge.svg
    :target: https://github.com/thombashi/allpairspy/actions?query=workflow%3ATests
    :alt: Linux/macOS/Windows CI status

.. image:: https://coveralls.io/repos/github/thombashi/allpairspy/badge.svg?branch=master
    :target: https://coveralls.io/github/thombashi/allpairspy?branch=master
    :alt: Test coverage


AllPairs test combinations generator
------------------------------------------------
AllPairs is an open source test combinations generator written in
Python, developed and maintained by MetaCommunications Engineering.
The generator allows one to create a set of tests using "pairwise
combinations" method, reducing a number of combinations of variables
into a lesser set that covers most situations.

For more info on pairwise testing see http://www.pairwise.org.


Features
--------
* Produces good enough dataset.
* Pythonic, iterator-style enumeration interface.
* Allows to filter out "invalid" combinations during search for the next combination.
* Goes beyond pairs! If/when required can generate n-wise combinations.


Get Started
---------------

Basic Usage
==================
:Sample Code:
    .. code:: python

        from allpairspy import AllPairs

        parameters = [
            ["Brand X", "Brand Y"],
            ["98", "NT", "2000", "XP"],
            ["Internal", "Modem"],
            ["Salaried", "Hourly", "Part-Time", "Contr."],
            [6, 10, 15, 30, 60],
        ]

        print("PAIRWISE:")
        for i, pairs in enumerate(AllPairs(parameters)):
            print("{:2d}: {}".format(i, pairs))

:Output:
    .. code::

        PAIRWISE:
         0: ['Brand X', '98', 'Internal', 'Salaried', 6]
         1: ['Brand Y', 'NT', 'Modem', 'Hourly', 6]
         2: ['Brand Y', '2000', 'Internal', 'Part-Time', 10]
         3: ['Brand X', 'XP', 'Modem', 'Contr.', 10]
         4: ['Brand X', '2000', 'Modem', 'Part-Time', 15]
         5: ['Brand Y', 'XP', 'Internal', 'Hourly', 15]
         6: ['Brand Y', '98', 'Modem', 'Salaried', 30]
         7: ['Brand X', 'NT', 'Internal', 'Contr.', 30]
         8: ['Brand X', '98', 'Internal', 'Hourly', 60]
         9: ['Brand Y', '2000', 'Modem', 'Contr.', 60]
        10: ['Brand Y', 'NT', 'Modem', 'Salaried', 60]
        11: ['Brand Y', 'XP', 'Modem', 'Part-Time', 60]
        12: ['Brand Y', '2000', 'Modem', 'Hourly', 30]
        13: ['Brand Y', '98', 'Modem', 'Contr.', 15]
        14: ['Brand Y', 'XP', 'Modem', 'Salaried', 15]
        15: ['Brand Y', 'NT', 'Modem', 'Part-Time', 15]
        16: ['Brand Y', 'XP', 'Modem', 'Part-Time', 30]
        17: ['Brand Y', '98', 'Modem', 'Part-Time', 6]
        18: ['Brand Y', '2000', 'Modem', 'Salaried', 6]
        19: ['Brand Y', '98', 'Modem', 'Salaried', 10]
        20: ['Brand Y', 'XP', 'Modem', 'Contr.', 6]
        21: ['Brand Y', 'NT', 'Modem', 'Hourly', 10]


Filtering
==================
You can restrict pairs by setting filtering function to ``filter_func`` at
``AllPairs`` constructor.

:Sample Code:
    .. code:: python

        from allpairspy import AllPairs

        def is_valid_combination(row):
            """
            This is a filtering function. Filtering functions should return True
            if combination is valid and False otherwise.

            Test row that is passed here can be incomplete.
            To prevent search for unnecessary items filtering function
            is executed with found subset of data to validate it.
            """

            n = len(row)

            if n > 1:
                # Brand Y does not support Windows 98
                if "98" == row[1] and "Brand Y" == row[0]:
                    return False

                # Brand X does not work with XP
                if "XP" == row[1] and "Brand X" == row[0]:
                    return False

            if n > 4:
                # Contractors are billed in 30 min increments
                if "Contr." == row[3] and row[4] < 30:
                    return False

            return True

        parameters = [
            ["Brand X", "Brand Y"],
            ["98", "NT", "2000", "XP"],
            ["Internal", "Modem"],
            ["Salaried", "Hourly", "Part-Time", "Contr."],
            [6, 10, 15, 30, 60]
        ]

        print("PAIRWISE:")
        for i, pairs in enumerate(AllPairs(parameters, filter_func=is_valid_combination)):
            print("{:2d}: {}".format(i, pairs))

:Output:
    .. code::

        PAIRWISE:
         0: ['Brand X', '98', 'Internal', 'Salaried', 6]
         1: ['Brand Y', 'NT', 'Modem', 'Hourly', 6]
         2: ['Brand Y', '2000', 'Internal', 'Part-Time', 10]
         3: ['Brand X', '2000', 'Modem', 'Contr.', 30]
         4: ['Brand X', 'NT', 'Internal', 'Contr.', 60]
         5: ['Brand Y', 'XP', 'Modem', 'Salaried', 60]
         6: ['Brand X', '98', 'Modem', 'Part-Time', 15]
         7: ['Brand Y', 'XP', 'Internal', 'Hourly', 15]
         8: ['Brand Y', 'NT', 'Internal', 'Part-Time', 30]
         9: ['Brand X', '2000', 'Modem', 'Hourly', 10]
        10: ['Brand Y', 'XP', 'Modem', 'Contr.', 30]
        11: ['Brand Y', '2000', 'Modem', 'Salaried', 15]
        12: ['Brand Y', 'NT', 'Modem', 'Salaried', 10]
        13: ['Brand Y', 'XP', 'Modem', 'Part-Time', 6]
        14: ['Brand Y', '2000', 'Modem', 'Contr.', 60]


Data Source: OrderedDict
====================================
You can use ``collections.OrderedDict`` instance as an argument for ``AllPairs`` constructor.
Pairs will be returned as ``collections.namedtuple`` instances.

:Sample Code:
    .. code:: python

        from collections import OrderedDict
        from allpairspy import AllPairs

        parameters = OrderedDict({
            "brand": ["Brand X", "Brand Y"],
            "os": ["98", "NT", "2000", "XP"],
            "minute": [15, 30, 60],
        })

        print("PAIRWISE:")
        for i, pairs in enumerate(AllPairs(parameters)):
            print("{:2d}: {}".format(i, pairs))

:Sample Code:
    .. code::

        PAIRWISE:
         0: Pairs(brand='Brand X', os='98', minute=15)
         1: Pairs(brand='Brand Y', os='NT', minute=15)
         2: Pairs(brand='Brand Y', os='2000', minute=30)
         3: Pairs(brand='Brand X', os='XP', minute=30)
         4: Pairs(brand='Brand X', os='2000', minute=60)
         5: Pairs(brand='Brand Y', os='XP', minute=60)
         6: Pairs(brand='Brand Y', os='98', minute=60)
         7: Pairs(brand='Brand X', os='NT', minute=60)
         8: Pairs(brand='Brand X', os='NT', minute=30)
         9: Pairs(brand='Brand X', os='98', minute=30)
        10: Pairs(brand='Brand X', os='XP', minute=15)
        11: Pairs(brand='Brand X', os='2000', minute=15)


Parameterized testing with pairwise by using pytest
====================================================================

Parameterized testing: valee matrix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
:Sample Code:
    .. code:: python

        import pytest
        from allpairspy import AllPairs

        def function_to_be_tested(brand, operating_system, minute) -> bool:
            # do something
            return True

        class TestParameterized(object):
            @pytest.mark.parametrize(["brand", "operating_system", "minute"], [
                values for values in AllPairs([
                    ["Brand X", "Brand Y"],
                    ["98", "NT", "2000", "XP"],
                    [10, 15, 30, 60]
                ])
            ])
            def test(self, brand, operating_system, minute):
                assert function_to_be_tested(brand, operating_system, minute)

:Output:
    .. code::

        $ py.test test_parameterize.py -v
        ============================= test session starts ==============================
        ...
        collected 16 items

        test_parameterize.py::TestParameterized::test[Brand X-98-10] PASSED      [  6%]
        test_parameterize.py::TestParameterized::test[Brand Y-NT-10] PASSED      [ 12%]
        test_parameterize.py::TestParameterized::test[Brand Y-2000-15] PASSED    [ 18%]
        test_parameterize.py::TestParameterized::test[Brand X-XP-15] PASSED      [ 25%]
        test_parameterize.py::TestParameterized::test[Brand X-2000-30] PASSED    [ 31%]
        test_parameterize.py::TestParameterized::test[Brand Y-XP-30] PASSED      [ 37%]
        test_parameterize.py::TestParameterized::test[Brand Y-98-60] PASSED      [ 43%]
        test_parameterize.py::TestParameterized::test[Brand X-NT-60] PASSED      [ 50%]
        test_parameterize.py::TestParameterized::test[Brand X-NT-30] PASSED      [ 56%]
        test_parameterize.py::TestParameterized::test[Brand X-98-30] PASSED      [ 62%]
        test_parameterize.py::TestParameterized::test[Brand X-XP-60] PASSED      [ 68%]
        test_parameterize.py::TestParameterized::test[Brand X-2000-60] PASSED    [ 75%]
        test_parameterize.py::TestParameterized::test[Brand X-2000-10] PASSED    [ 81%]
        test_parameterize.py::TestParameterized::test[Brand X-XP-10] PASSED      [ 87%]
        test_parameterize.py::TestParameterized::test[Brand X-98-15] PASSED      [ 93%]
        test_parameterize.py::TestParameterized::test[Brand X-NT-15] PASSED      [100%]

Parameterized testing: OrderedDict
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
:Sample Code:
    .. code:: python

        import pytest
        from allpairspy import AllPairs

        def function_to_be_tested(brand, operating_system, minute) -> bool:
            # do something
            return True

        class TestParameterized(object):
            @pytest.mark.parametrize(
                ["pair"],
                [
                    [pair]
                    for pair in AllPairs(
                        OrderedDict(
                            {
                                "brand": ["Brand X", "Brand Y"],
                                "operating_system": ["98", "NT", "2000", "XP"],
                                "minute": [10, 15, 30, 60],
                            }
                        )
                    )
                ],
            )
            def test(self, pair):
                assert function_to_be_tested(pair.brand, pair.operating_system, pair.minute)


Other Examples
=================
Other examples could be found in `examples <https://github.com/thombashi/allpairspy/tree/master/examples>`__ directory.


Installation
------------

Installation: pip
==================================
::

    pip install allpairspy

Installation: apt
==================================
You can install the package by ``apt`` via a Personal Package Archive (`PPA <https://launchpad.net/~thombashi/+archive/ubuntu/ppa>`__):

::

    sudo add-apt-repository ppa:thombashi/ppa
    sudo apt update
    sudo apt install python3-allpairspy


Known issues
------------
* Not optimal - there are tools that can create smaller set covering
  all the pairs. However, they are missing some other important
  features and/or do not integrate well with Python.

* Lousy written filtering function may lead to full permutation of parameters.

* Version 2.0 has become slower (a side-effect of introducing ability to produce n-wise combinations).


Dependencies
------------
Python 3.5+
no external dependencies.


Sponsors
------------
.. image:: https://avatars0.githubusercontent.com/u/44389260?s=48&u=6da7176e51ae2654bcfd22564772ef8a3bb22318&v=4
   :target: https://github.com/chasbecker
   :alt: chasbecker

`Become a sponsor <https://github.com/sponsors/thombashi>`__
