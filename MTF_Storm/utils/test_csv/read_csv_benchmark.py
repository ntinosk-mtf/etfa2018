import csv
import os
import cProfile
import time
import numpy
import pandas
import warnings

# Make sure those files in the same folder as benchmark_python.py
# As the name indicates:
# - '1col.csv' is a CSV file with 1 column
# - '3col.csv' is a CSV file with 3 column
filename1 = '1col.csv'
filename3 = '3col.csv'
csv_delimiter = ','
debug = False

def open_with_python_csv(filename):
    '''
    https://docs.python.org/2/library/csv.html
    '''
    data =[]
    with open(filename, 'rb') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=csv_delimiter, quotechar='|')
        for row in csvreader:
            data.append(row)    
    return data

def open_with_python_csv_cast_as_float(filename):
    '''
    https://docs.python.org/2/library/csv.html
    '''
    data =[]
    with open(filename, 'rb') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=csv_delimiter, quotechar='|')
        for row in csvreader:
            data.append(map(float, row))    
    return data

def open_with_python_csv_list(filename):
    '''
    https://docs.python.org/2/library/csv.html
    '''
    data =[]
    with open(filename, 'rb') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=csv_delimiter, quotechar='|')
        data = list(csvreader)    
    return data


def open_with_numpy_loadtxt(filename):
    '''
    http://stackoverflow.com/questions/4315506/load-csv-into-2d-matrix-with-numpy-for-plotting
    '''
    data = numpy.loadtxt(open(filename,'rb'),delimiter=csv_delimiter,skiprows=0)
    return data

def open_with_pandas_read_csv(filename):
    df = pandas.read_csv(filename, sep=csv_delimiter)
    data = df.values
    print data[999]
    print len(data), data[1]
    print len(data), data[2]
    
    return data    


def benchmark(function_name):  
    start_time = time.clock()
    data = function_name(filename1)       
    if debug: print data[0] 
    data = function_name(filename3)
    if debug: print data[0]
    print function_name.__name__ + ': ' + str(time.clock() - start_time), "seconds"


def benchmark_numpy_fromfile():
    '''
    http://docs.scipy.org/doc/numpy/reference/generated/numpy.fromfile.html
    Do not rely on the combination of tofile and fromfile for data storage, 
    as the binary files generated are are not platform independent.
    In particular, no byte-order or data-type information is saved.
    Data can be stored in the platform independent .npy format using
    save and load instead.

    Note that fromfile will create a one-dimensional array containing your data,
    so you might need to reshape it afterward.
    '''
    #ignore the 'tmpnam is a potential security risk to your program' warning
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', RuntimeWarning)
        fname1 = os.tmpnam()
        fname3 = os.tmpnam()

    data = open_with_numpy_loadtxt(filename1)
    if debug: print data[0]
    data.tofile(fname1)
    data = open_with_numpy_loadtxt(filename3)
    if debug: print data[0]
    data.tofile(fname3)
    if debug: print data.shape
    fname3shape = data.shape
    start_time = time.clock()
    data = numpy.fromfile(fname1, dtype=numpy.float64) # you might need to switch to float32. List of types: http://docs.scipy.org/doc/numpy/reference/arrays.dtypes.html
    if debug: print len(data), data[0], data.shape
    data = numpy.fromfile(fname3, dtype=numpy.float64)
    data = data.reshape(fname3shape)
    if debug: print len(data), data[0], data.shape    
    print 'Numpy fromfile: ' + str(time.clock() - start_time), "seconds"
    print data[0]

def benchmark_numpy_save_load():
    '''
    http://docs.scipy.org/doc/numpy/reference/generated/numpy.fromfile.html
    Do not rely on the combination of tofile and fromfile for data storage, 
    as the binary files generated are are not platform independent.
    In particular, no byte-order or data-type information is saved.
    Data can be stored in the platform independent .npy format using
    save and load instead.

    Note that fromfile will create a one-dimensional array containing your data,
    so you might need to reshape it afterward.
    '''
    #ignore the 'tmpnam is a potential security risk to your program' warning
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', RuntimeWarning)
        fname1 = os.tmpnam()
        fname3 = os.tmpnam()

    data = open_with_numpy_loadtxt(filename1)
    if debug: print data[0]    
    numpy.save(fname1, data)    
    data = open_with_numpy_loadtxt(filename3)
    if debug: print data[0]    
    numpy.save(fname3, data)    
    if debug: print data.shape
    fname3shape = data.shape
    start_time = time.clock()
    data = numpy.load(fname1 + '.npy')
    if debug: print len(data), data[0], data.shape
    data = numpy.load(fname3 + '.npy')
    #data = data.reshape(fname3shape)
    if debug: print len(data), data[0], data.shape 
    print len(data), data[0]   
    print 'Numpy load: ' + str(time.clock() - start_time), "seconds"


def main():
    number_of_runs = 20
    results = []

    benchmark_functions = ['benchmark(open_with_python_csv)', 
                           'benchmark(open_with_python_csv_list)',
                           #'benchmark(open_with_python_csv_cast_as_float)',
                           'benchmark(open_with_numpy_loadtxt)',
                           'benchmark(open_with_pandas_read_csv)',
                           'benchmark_numpy_fromfile()',
                           'benchmark_numpy_save_load()']
    # Compute benchmark
    for run_number in range(number_of_runs):
        run_results = []
        for benchmark_function in benchmark_functions:
            run_results.append(eval(benchmark_function))
            results.append(run_results)

    # Display benchmark's results
    print results
    results = numpy.array(results)
    numpy.set_printoptions(precision=10) # http://stackoverflow.com/questions/2891790/pretty-printing-of-numpy-array
    numpy.set_printoptions(suppress=True)  # suppress suppresses the use of scientific notation for small numbers:
    print numpy.mean(results, axis=0)
    print numpy.std(results, axis=0)    

    #Another library, but not free: https://store.continuum.io/cshop/iopro/

if __name__ == "__main__":
    #cProfile.run('main()') # if you want to do some profiling
    main()  