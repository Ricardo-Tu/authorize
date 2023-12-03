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
#include "../HwInfo.h"


PYBIND11_MODULE(HwInfo, m)
{
    m.doc() = "HwInfo module";

    m.def("GetHwInfo", &GetHwInfo);
    m.def("CheckHwInfo", &CheckHwInfo);
}
