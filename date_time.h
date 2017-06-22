#ifndef __DATE_TIME_H__
#define __DATE_TIME_H__

#include <iostream>
#include <vector>
#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/algorithm/string.hpp>
#include <ctype.h>

using namespace std;
using namespace boost;
using namespace boost::posix_time;
using namespace boost::gregorian;
using namespace boost::algorithm;

class CDateTime
{
public:
	CDateTime();
	virtual ~CDateTime();

	string before_current_time(int sec);
	string current_time();
	string current_iso_time();
	time_t date_time_2_timestamp(string strt);
	string timestamp_2_string(time_t t);
	void echo_time();

};


#endif

