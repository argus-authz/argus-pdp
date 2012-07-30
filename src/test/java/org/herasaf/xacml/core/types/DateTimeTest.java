/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.herasaf.xacml.core.types;

import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import junit.framework.TestCase;

/**
 * Test the HERASAF DateTime, Date and Time format in UTC (with the Z indicator)
 */
public class DateTimeTest extends TestCase {

    private DatatypeFactory datatypeFactory;

    private GregorianCalendar now= null;

    private GregorianCalendar nowUTC= null;

    /** {@inheritDoc} */
    protected void setUp() throws Exception {
        super.setUp();
        datatypeFactory= DatatypeFactory.newInstance();
        now= new GregorianCalendar();
        nowUTC= new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        System.out.println("-------" + this.getName() + "---------");
    }

    public void testDateTime() {
        XMLGregorianCalendar xmlDateTime= datatypeFactory.newXMLGregorianCalendar(now);
        xmlDateTime.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        String dateTime= xmlDateTime.toXMLFormat();
        System.out.println("parsing: " + dateTime);
        DateTime dt= new DateTime(dateTime);
        System.out.println("XACML: " + dt);
    }

    public void testDateTimeUTC() {
        XMLGregorianCalendar xmlDateTime= datatypeFactory.newXMLGregorianCalendar(nowUTC);
        xmlDateTime.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        String dateTimeUTC= xmlDateTime.toXMLFormat();
        System.out.println("parsing: " + dateTimeUTC);
        DateTime dt= new DateTime(dateTimeUTC);
        System.out.println("XACML: " + dt);
    }

    public void testDate() {
        XMLGregorianCalendar xmlDate= datatypeFactory.newXMLGregorianCalendar(now);
        xmlDate.setHour(DatatypeConstants.FIELD_UNDEFINED);
        xmlDate.setMinute(DatatypeConstants.FIELD_UNDEFINED);
        xmlDate.setSecond(DatatypeConstants.FIELD_UNDEFINED);
        xmlDate.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        String date= xmlDate.toXMLFormat();
        System.out.println("parsing: " + date);
        Date d= new Date(date);
        System.out.println("XACML: " + d);
    }

    public void disabled_testDateUTC() {
        XMLGregorianCalendar xmlDate= datatypeFactory.newXMLGregorianCalendar(nowUTC);
        xmlDate.setHour(DatatypeConstants.FIELD_UNDEFINED);
        xmlDate.setMinute(DatatypeConstants.FIELD_UNDEFINED);
        xmlDate.setSecond(DatatypeConstants.FIELD_UNDEFINED);
        xmlDate.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        String dateUTC= xmlDate.toXMLFormat();
        System.out.println("parsing: " + dateUTC);
        Date d= new Date(dateUTC);
        System.out.println("XACML: " + d);
    }

    public void testTime() {
        XMLGregorianCalendar xmlTime= datatypeFactory.newXMLGregorianCalendar(now);
        xmlTime.setYear(DatatypeConstants.FIELD_UNDEFINED);
        xmlTime.setMonth(DatatypeConstants.FIELD_UNDEFINED);
        xmlTime.setDay(DatatypeConstants.FIELD_UNDEFINED);
        xmlTime.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        String time= xmlTime.toXMLFormat();
        System.out.println("parsing: " + time);
        Time t= new Time(time);
        System.out.println("XACML: " + t);
    }

    public void disabled_testTimeUTC() {
        XMLGregorianCalendar xmlTime= datatypeFactory.newXMLGregorianCalendar(nowUTC);
        xmlTime.setYear(DatatypeConstants.FIELD_UNDEFINED);
        xmlTime.setMonth(DatatypeConstants.FIELD_UNDEFINED);
        xmlTime.setDay(DatatypeConstants.FIELD_UNDEFINED);
        xmlTime.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        String timeUTC= xmlTime.toXMLFormat();
        System.out.println("parsing: " + timeUTC);
        Time t= new Time(timeUTC);
        System.out.println("XACML: " + t);
    }

}
