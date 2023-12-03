#include <pybind11/pybind11.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>
#include <iostream>
#include <list>
#include <string>
#include <list>
#include <map>
#include <sstream>
#include <cpprest/http_client.h>
#include "../HwInfo_authorize.h"


PYBIND11_MODULE(HwInfo_authorize, m)
{
    m.doc() = "HwInfo_authorize module";

    m.def("authorize", &authorize);
}
