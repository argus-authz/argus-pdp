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

package org.glite.authz.pdp.server;

import java.util.HashMap;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.profile.AuthorizationProfileConstants;
import org.glite.authz.pdp.xacml.FQANDataTypeAttribute;
import org.glite.authz.pdp.xacml.FQANEqualFunction;
import org.glite.authz.pdp.xacml.FQANRegexpFunction;

import org.herasaf.xacml.core.combiningAlgorithm.policy.PolicyCombiningAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.policy.impl.PolicyDenyOverridesAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.policy.impl.PolicyFirstApplicableAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.policy.impl.PolicyOnlyOneApplicableAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.policy.impl.PolicyOrderedDenyOverridesAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.policy.impl.PolicyOrderedPermitOverridesAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.policy.impl.PolicyPermitOverridesAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.rule.RuleCombiningAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.rule.impl.RuleDenyOverridesAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.rule.impl.RuleFirstApplicableAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.rule.impl.RuleOrderedDenyOverridesAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.rule.impl.RuleOrderedPermitOverridesAlgorithm;
import org.herasaf.xacml.core.combiningAlgorithm.rule.impl.RulePermitOverridesAlgorithm;
import org.herasaf.xacml.core.converter.URNToDataTypeConverter;
import org.herasaf.xacml.core.converter.URNToFunctionConverter;
import org.herasaf.xacml.core.converter.URNToPolicyCombiningAlgorithmConverter;
import org.herasaf.xacml.core.converter.URNToRuleCombiningAlgorithmConverter;
import org.herasaf.xacml.core.dataTypeAttribute.DataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.AnyURIDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.Base64BinaryDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.BooleanDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.DateDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.DateTimeDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.DayTimeDurationDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.DnsNameDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.DoubleDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.HexBinaryDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.IntegerDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.IpAddressDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.RFC822NameDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.StringDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.TimeDataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.X500DataTypeAttribute;
import org.herasaf.xacml.core.dataTypeAttribute.impl.YearMonthDurationDataTypeAttribute;
import org.herasaf.xacml.core.function.Function;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.DoubleAbsFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.DoubleAddFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.DoubleDivideFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.DoubleMultiplyFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.DoubleSubtractFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.FloorFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.IntegerAbsFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.IntegerAddFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.IntegerDivideFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.IntegerModFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.IntegerMultiplyFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.IntegerSubtractFunction;
import org.herasaf.xacml.core.function.impl.arithmeticFunctions.RoundFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.AnyUriBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.AnyUriBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.AnyUriIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.AnyUriOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.Base64BinaryBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.Base64BinaryBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.Base64BinaryIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.Base64BinaryOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.BooleanBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.BooleanBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.BooleanIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.BooleanOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateTimeBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateTimeBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateTimeIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DateTimeOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DayTimeDurationBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DayTimeDurationBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DayTimeDurationIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DayTimeDurationOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DoubleBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DoubleBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DoubleIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.DoubleOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.HexBinaryBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.HexBinaryBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.HexBinaryIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.HexBinaryOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.IntegerBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.IntegerBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.IntegerIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.IntegerOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.RFC822NameBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.RFC822NameBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.RFC822NameIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.RFC822NameOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.StringBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.StringBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.StringIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.StringOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.TimeBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.TimeBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.TimeIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.TimeOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.X500NameBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.X500NameBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.X500NameIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.X500NameOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.YearMonthDurationBagFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.YearMonthDurationBagSizeFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.YearMonthDurationIsInFunction;
import org.herasaf.xacml.core.function.impl.bagFunctions.YearMonthDurationOneAndOnlyFunction;
import org.herasaf.xacml.core.function.impl.dateAndTimeArithmeticFunctions.DateAddYearMonthDurationFunction;
import org.herasaf.xacml.core.function.impl.dateAndTimeArithmeticFunctions.DateSubtractYearMonthDurationFunction;
import org.herasaf.xacml.core.function.impl.dateAndTimeArithmeticFunctions.DateTimeAddDayTimeDurationFunction;
import org.herasaf.xacml.core.function.impl.dateAndTimeArithmeticFunctions.DateTimeAddYearMonthDurationFunction;
import org.herasaf.xacml.core.function.impl.dateAndTimeArithmeticFunctions.DateTimeSubtractDayTimeDurationFunction;
import org.herasaf.xacml.core.function.impl.dateAndTimeArithmeticFunctions.DateTimeSubtractYearMonthDurationFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.AnyURIEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.Base64BinaryEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.BooleanEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.DateEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.DateTimeEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.DayTimeDurationEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.DoubleEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.HexBinaryEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.IntegerEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.Rfc822NameEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.StringEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.TimeEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.X500NameEqualFunction;
import org.herasaf.xacml.core.function.impl.equalityPredicates.YearMonthDurationEqualFunction;
import org.herasaf.xacml.core.function.impl.higherOrderBagFunctions.AllOfAllFunction;
import org.herasaf.xacml.core.function.impl.higherOrderBagFunctions.AllOfAnyFunction;
import org.herasaf.xacml.core.function.impl.higherOrderBagFunctions.AllOfFunction;
import org.herasaf.xacml.core.function.impl.higherOrderBagFunctions.AnyOfAllFunction;
import org.herasaf.xacml.core.function.impl.higherOrderBagFunctions.AnyOfAnyFunction;
import org.herasaf.xacml.core.function.impl.higherOrderBagFunctions.AnyOfFunction;
import org.herasaf.xacml.core.function.impl.higherOrderBagFunctions.MapFunction;
import org.herasaf.xacml.core.function.impl.logicalFunctions.ANDFunction;
import org.herasaf.xacml.core.function.impl.logicalFunctions.NOFFunction;
import org.herasaf.xacml.core.function.impl.logicalFunctions.NotFunction;
import org.herasaf.xacml.core.function.impl.logicalFunctions.ORFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateGreaterThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateGreaterThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateLessThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateLessThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateTimeGreaterThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateTimeGreaterThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateTimeLessThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.DateTimeLessThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.StringGreaterThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.StringGreaterThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.StringLessThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.StringLessThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.TimeGreaterThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.TimeGreaterThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.TimeInRangeFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.TimeLessThanFunction;
import org.herasaf.xacml.core.function.impl.nonNumericComparisonFunctions.TimeLessThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.DoubleGreaterThanFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.DoubleGreaterThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.DoubleLessThanFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.DoubleLessThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.IntegerGreaterThanFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.IntegerGreaterThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.IntegerLessThanFunction;
import org.herasaf.xacml.core.function.impl.numericComparisonFunctions.IntegerLessThanOrEqualFunction;
import org.herasaf.xacml.core.function.impl.numericDataTypeConversionFunctions.DoubleToIntegerFunction;
import org.herasaf.xacml.core.function.impl.numericDataTypeConversionFunctions.IntegerToDoubleFunction;
import org.herasaf.xacml.core.function.impl.regularExpressionBasedFunctions.AnyURIRegexpMatchFunction;
import org.herasaf.xacml.core.function.impl.regularExpressionBasedFunctions.DNSNameRegexpMatchFunction;
import org.herasaf.xacml.core.function.impl.regularExpressionBasedFunctions.IPAddressRegexpMatchFunction;
import org.herasaf.xacml.core.function.impl.regularExpressionBasedFunctions.RFC822NameRegexpMatchFunction;
import org.herasaf.xacml.core.function.impl.regularExpressionBasedFunctions.StringRegexpMatchFunction;
import org.herasaf.xacml.core.function.impl.regularExpressionBasedFunctions.X500NameRegexpMatchFunction;
import org.herasaf.xacml.core.function.impl.setFunction.AnyURIAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.AnyURIIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.AnyURISetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.AnyURISubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.AnyURIUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.Base64BinaryAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.Base64BinaryIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.Base64BinarySetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.Base64BinarySubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.Base64BinaryUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.BooleanAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.BooleanIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.BooleanSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.BooleanSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.BooleanUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateTimeAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateTimeIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateTimeSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateTimeSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateTimeUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DateUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DayTimeDurationAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DayTimeDurationIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DayTimeDurationSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DayTimeDurationSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DayTimeDurationUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DoubleAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DoubleIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DoubleSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DoubleSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.DoubleUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.HexBinaryAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.HexBinaryIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.HexBinarySetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.HexBinarySubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.HexBinaryUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.IntegerAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.IntegerIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.IntegerSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.IntegerSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.IntegerUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.RFC822NameAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.RFC822NameIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.RFC822NameSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.RFC822NameSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.RFC822NameUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.StringAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.StringIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.StringSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.StringSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.StringUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.TimeAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.TimeIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.TimeSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.TimeSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.TimeUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.X500NameAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.X500NameIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.X500NameSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.X500NameSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.X500NameUnionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.YearMonthDurationAtLeastOneMemberOfFunction;
import org.herasaf.xacml.core.function.impl.setFunction.YearMonthDurationIntersectionFunction;
import org.herasaf.xacml.core.function.impl.setFunction.YearMonthDurationSetEqualsFunction;
import org.herasaf.xacml.core.function.impl.setFunction.YearMonthDurationSubsetFunction;
import org.herasaf.xacml.core.function.impl.setFunction.YearMonthDurationUnionFunction;
import org.herasaf.xacml.core.function.impl.specialMatchFunctions.RFC822NameMatchFunction;
import org.herasaf.xacml.core.function.impl.specialMatchFunctions.X500NameMatchFunction;
import org.herasaf.xacml.core.function.impl.stringConversionFunctions.StringNormalizeSpaceFunction;
import org.herasaf.xacml.core.function.impl.stringConversionFunctions.StringNormalizeToLowerCaseFunction;
import org.herasaf.xacml.core.function.impl.stringFunctions.StringConcatenateFunction;
import org.herasaf.xacml.core.function.impl.stringFunctions.UriStringConcatenateFunction;
import org.herasaf.xacml.core.simplePDP.initializers.JAXBInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Initializes the core HERASAF library. */
@ThreadSafe
public final class HerasAFBootstrap {

    /** Class logger. */
    private static final Logger LOG = LoggerFactory.getLogger(HerasAFBootstrap.class);

    /** Bootstraps the HERASAF library. */
    public static void bootstap() {
        initializeJAXB();
        initializeDataTypes();
        initializeFunctions();
        initializePolicyCombiningAlgorithms();
        initializeRuleCombiningAlgorithms();

    }

    /** Initializes the JAXB configuration used to unmarshall policies. */
    private static void initializeJAXB() {

        JAXBInitializer jaxbInitializer= new JAXBInitializer();
        jaxbInitializer.run();
//        try {
//            JAXBContext jaxbCtx = JAXBContext
//                    .newInstance("org.herasaf.xacml.core.policy.impl:org.herasaf.xacml.core.context.impl");
//
//            ContextAndPolicyConfiguration capConfig = new ContextAndPolicyConfiguration();
//            capConfig.setContext(jaxbCtx);
//
//            ContextAndPolicy.setPolicyProfile(capConfig);
//            ContextAndPolicy.setRequestCtxProfile(capConfig);
//            ContextAndPolicy.setRequestCtxProfile(capConfig);
//        } catch (JAXBException e) {
//            LOG.error("Unable to initialize JAXB", e);
//            throw new RuntimeException(e);
//        }
    }

    /** Initialize all the standard attribute data types. */
    private static void initializeDataTypes() {
        HashMap<String, DataTypeAttribute<?>> dataTypes = new HashMap<String, DataTypeAttribute<?>>();
        dataTypes.put(AnyURIDataTypeAttribute.ID, new AnyURIDataTypeAttribute());
        dataTypes.put(Base64BinaryDataTypeAttribute.ID, new Base64BinaryDataTypeAttribute());
        dataTypes.put(BooleanDataTypeAttribute.ID, new BooleanDataTypeAttribute());
        dataTypes.put(DateDataTypeAttribute.ID, new DateDataTypeAttribute());
        dataTypes.put(DateTimeDataTypeAttribute.ID, new DateTimeDataTypeAttribute());
        dataTypes.put(DayTimeDurationDataTypeAttribute.ID, new DayTimeDurationDataTypeAttribute());
        dataTypes.put(DnsNameDataTypeAttribute.ID, new DnsNameDataTypeAttribute());
        dataTypes.put(DoubleDataTypeAttribute.ID, new DoubleDataTypeAttribute());
        dataTypes.put(HexBinaryDataTypeAttribute.ID, new HexBinaryDataTypeAttribute());
        dataTypes.put(IntegerDataTypeAttribute.ID, new IntegerDataTypeAttribute());
        dataTypes.put(IpAddressDataTypeAttribute.ID, new IpAddressDataTypeAttribute());
        dataTypes.put(RFC822NameDataTypeAttribute.ID, new RFC822NameDataTypeAttribute());
        dataTypes.put(StringDataTypeAttribute.ID, new StringDataTypeAttribute());
        dataTypes.put(TimeDataTypeAttribute.ID, new TimeDataTypeAttribute());
        dataTypes.put(X500DataTypeAttribute.ID, new X500DataTypeAttribute());
        dataTypes.put(YearMonthDurationDataTypeAttribute.ID, new YearMonthDurationDataTypeAttribute());
        dataTypes.put(AuthorizationProfileConstants.DATATYPE_FQAN, new FQANDataTypeAttribute());

        URNToDataTypeConverter.setDataTypeAttributes(dataTypes);
    }

    /** Initialize all the standard policy functions types. */
    private static void initializeFunctions() {
        HashMap<String, Function> functions = new HashMap<String, Function>();

        // arithmetic functions
        functions.put(DoubleAbsFunction.ID, new DoubleAbsFunction());
        functions.put(DoubleAddFunction.ID, new DoubleAddFunction());
        functions.put(DoubleDivideFunction.ID, new DoubleDivideFunction());
        functions.put(DoubleMultiplyFunction.ID, new DoubleMultiplyFunction());
        functions.put(DoubleSubtractFunction.ID, new DoubleSubtractFunction());
        functions.put(FloorFunction.ID, new FloorFunction());
        functions.put(IntegerAbsFunction.ID, new IntegerAbsFunction());
        functions.put(IntegerAddFunction.ID, new IntegerAddFunction());
        functions.put(IntegerDivideFunction.ID, new IntegerAddFunction());
        functions.put(IntegerDivideFunction.ID, new IntegerDivideFunction());
        functions.put(IntegerModFunction.ID, new IntegerModFunction());
        functions.put(IntegerMultiplyFunction.ID, new IntegerMultiplyFunction());
        functions.put(IntegerSubtractFunction.ID, new IntegerSubtractFunction());
        functions.put(RoundFunction.ID, new RoundFunction());

        // bag functions
        functions.put(AnyUriBagFunction.ID, new AnyUriBagFunction());
        functions.put(AnyUriBagSizeFunction.ID, new AnyUriBagSizeFunction());
        functions.put(AnyUriIsInFunction.ID, new AnyUriIsInFunction());
        functions.put(AnyUriOneAndOnlyFunction.ID, new AnyUriOneAndOnlyFunction());
        functions.put(Base64BinaryBagFunction.ID, new Base64BinaryBagFunction());
        functions.put(Base64BinaryBagSizeFunction.ID, new Base64BinaryBagSizeFunction());
        functions.put(Base64BinaryIsInFunction.ID, new Base64BinaryIsInFunction());
        functions.put(Base64BinaryOneAndOnlyFunction.ID, new Base64BinaryOneAndOnlyFunction());
        functions.put(BooleanBagFunction.ID, new BooleanBagFunction());
        functions.put(BooleanBagSizeFunction.ID, new BooleanBagSizeFunction());
        functions.put(BooleanIsInFunction.ID, new BooleanIsInFunction());
        functions.put(BooleanOneAndOnlyFunction.ID, new BooleanOneAndOnlyFunction());
        functions.put(DateBagFunction.ID, new DateBagFunction());
        functions.put(DateBagSizeFunction.ID, new DateBagSizeFunction());
        functions.put(DateIsInFunction.ID, new DateIsInFunction());
        functions.put(DateOneAndOnlyFunction.ID, new DateOneAndOnlyFunction());
        functions.put(DateTimeBagFunction.ID, new DateTimeBagFunction());
        functions.put(DateTimeBagSizeFunction.ID, new DateTimeBagSizeFunction());
        functions.put(DateTimeIsInFunction.ID, new DateTimeIsInFunction());
        functions.put(DateTimeOneAndOnlyFunction.ID, new DateTimeOneAndOnlyFunction());
        functions.put(DayTimeDurationBagFunction.ID, new DayTimeDurationBagFunction());
        functions.put(DayTimeDurationBagSizeFunction.ID, new DayTimeDurationBagSizeFunction());
        functions.put(DayTimeDurationIsInFunction.ID, new DayTimeDurationIsInFunction());
        functions.put(DayTimeDurationOneAndOnlyFunction.ID, new DayTimeDurationOneAndOnlyFunction());
        functions.put(DoubleBagFunction.ID, new DoubleBagFunction());
        functions.put(DoubleBagSizeFunction.ID, new DoubleBagSizeFunction());
        functions.put(DoubleIsInFunction.ID, new DoubleIsInFunction());
        functions.put(DoubleOneAndOnlyFunction.ID, new DoubleOneAndOnlyFunction());
        functions.put(HexBinaryBagFunction.ID, new HexBinaryBagFunction());
        functions.put(HexBinaryBagSizeFunction.ID, new HexBinaryBagSizeFunction());
        functions.put(HexBinaryIsInFunction.ID, new HexBinaryIsInFunction());
        functions.put(HexBinaryOneAndOnlyFunction.ID, new HexBinaryOneAndOnlyFunction());
        functions.put(IntegerBagFunction.ID, new IntegerBagFunction());
        functions.put(IntegerBagSizeFunction.ID, new IntegerBagSizeFunction());
        functions.put(IntegerIsInFunction.ID, new IntegerIsInFunction());
        functions.put(IntegerOneAndOnlyFunction.ID, new IntegerOneAndOnlyFunction());
        functions.put(RFC822NameBagFunction.ID, new RFC822NameBagFunction());
        functions.put(RFC822NameBagSizeFunction.ID, new RFC822NameBagSizeFunction());
        functions.put(RFC822NameIsInFunction.ID, new RFC822NameIsInFunction());
        functions.put(RFC822NameOneAndOnlyFunction.ID, new RFC822NameOneAndOnlyFunction());
        functions.put(StringBagFunction.ID, new StringBagFunction());
        functions.put(StringBagSizeFunction.ID, new StringBagSizeFunction());
        functions.put(StringIsInFunction.ID, new StringIsInFunction());
        functions.put(StringOneAndOnlyFunction.ID, new StringOneAndOnlyFunction());
        functions.put(TimeBagFunction.ID, new TimeBagFunction());
        functions.put(TimeBagSizeFunction.ID, new TimeBagSizeFunction());
        functions.put(TimeIsInFunction.ID, new TimeIsInFunction());
        functions.put(TimeOneAndOnlyFunction.ID, new TimeOneAndOnlyFunction());
        functions.put(X500NameBagFunction.ID, new X500NameBagFunction());
        functions.put(X500NameBagSizeFunction.ID, new X500NameBagSizeFunction());
        functions.put(X500NameIsInFunction.ID, new X500NameIsInFunction());
        functions.put(X500NameOneAndOnlyFunction.ID, new X500NameOneAndOnlyFunction());
        functions.put(YearMonthDurationBagFunction.ID, new YearMonthDurationBagFunction());
        functions.put(YearMonthDurationBagSizeFunction.ID, new YearMonthDurationBagSizeFunction());
        functions.put(YearMonthDurationIsInFunction.ID, new YearMonthDurationIsInFunction());
        functions.put(YearMonthDurationOneAndOnlyFunction.ID, new YearMonthDurationOneAndOnlyFunction());

        // date/time arithmetic functions
        functions.put(DateAddYearMonthDurationFunction.ID, new DateAddYearMonthDurationFunction());
        functions.put(DateSubtractYearMonthDurationFunction.ID, new DateSubtractYearMonthDurationFunction());
        functions.put(DateTimeAddDayTimeDurationFunction.ID, new DateTimeAddDayTimeDurationFunction());
        functions.put(DateTimeAddYearMonthDurationFunction.ID, new DateTimeAddYearMonthDurationFunction());
        functions.put(DateTimeSubtractDayTimeDurationFunction.ID, new DateTimeSubtractDayTimeDurationFunction());
        functions.put(DateTimeSubtractYearMonthDurationFunction.ID, new DateTimeSubtractYearMonthDurationFunction());

        // equality functions
        functions.put(AnyURIEqualFunction.ID, new AnyURIEqualFunction());
        functions.put(Base64BinaryEqualFunction.ID, new Base64BinaryEqualFunction());
        functions.put(BooleanEqualFunction.ID, new BooleanEqualFunction());
        functions.put(DateEqualFunction.ID, new DateEqualFunction());
        functions.put(DateTimeEqualFunction.ID, new DateTimeEqualFunction());
        functions.put(DayTimeDurationEqualFunction.ID, new DayTimeDurationEqualFunction());
        functions.put(DoubleEqualFunction.ID, new DoubleEqualFunction());
        functions.put(HexBinaryEqualFunction.ID, new HexBinaryEqualFunction());
        functions.put(IntegerEqualFunction.ID, new IntegerEqualFunction());
        functions.put(Rfc822NameEqualFunction.ID, new Rfc822NameEqualFunction());
        functions.put(StringEqualFunction.ID, new StringEqualFunction());
        functions.put(TimeEqualFunction.ID, new TimeEqualFunction());
        functions.put(X500NameEqualFunction.ID, new X500NameEqualFunction());
        functions.put(YearMonthDurationEqualFunction.ID, new YearMonthDurationEqualFunction());
        functions.put(AuthorizationProfileConstants.ID_ALGORITHM_FQAN_EXACT_MATCH, new FQANEqualFunction());

        // higher order bag functions
        functions.put(AllOfAllFunction.ID, new AllOfAllFunction());
        functions.put(AllOfAnyFunction.ID, new AllOfAnyFunction());
        functions.put(AllOfFunction.ID, new AllOfAllFunction());
        functions.put(AnyOfAllFunction.ID, new AnyOfAllFunction());
        functions.put(AnyOfAnyFunction.ID, new AnyOfAnyFunction());
        functions.put(AnyOfFunction.ID, new AnyOfFunction());
        functions.put(MapFunction.ID, new MapFunction());

        // logical functions
        functions.put(ANDFunction.ID, new ANDFunction());
        functions.put(NOFFunction.ID, new NOFFunction());
        functions.put(NotFunction.ID, new NotFunction());
        functions.put(ORFunction.ID, new ORFunction());

        // non-numeric comparison functions
        functions.put(DateGreaterThanFunction.ID, new DateGreaterThanFunction());
        functions.put(DateGreaterThanOrEqualFunction.ID, new DateGreaterThanOrEqualFunction());
        functions.put(DateLessThanFunction.ID, new DateLessThanFunction());
        functions.put(DateLessThanOrEqualFunction.ID, new DateLessThanOrEqualFunction());
        functions.put(DateTimeGreaterThanFunction.ID, new DateTimeGreaterThanFunction());
        functions.put(DateTimeGreaterThanOrEqualFunction.ID, new DateTimeGreaterThanOrEqualFunction());
        functions.put(DateTimeLessThanFunction.ID, new DateTimeLessThanFunction());
        functions.put(DateTimeLessThanOrEqualFunction.ID, new DateTimeLessThanOrEqualFunction());
        functions.put(StringGreaterThanFunction.ID, new StringGreaterThanFunction());
        functions.put(StringGreaterThanOrEqualFunction.ID, new StringGreaterThanOrEqualFunction());
        functions.put(StringLessThanFunction.ID, new StringLessThanFunction());
        functions.put(StringLessThanOrEqualFunction.ID, new StringLessThanOrEqualFunction());
        functions.put(TimeGreaterThanFunction.ID, new TimeGreaterThanFunction());
        functions.put(TimeGreaterThanOrEqualFunction.ID, new TimeGreaterThanOrEqualFunction());
        functions.put(TimeInRangeFunction.ID, new TimeInRangeFunction());
        functions.put(TimeLessThanFunction.ID, new TimeLessThanFunction());
        functions.put(TimeLessThanOrEqualFunction.ID, new TimeLessThanOrEqualFunction());

        // numeric comparison functions
        functions.put(DoubleGreaterThanFunction.ID, new DoubleGreaterThanFunction());
        functions.put(DoubleGreaterThanOrEqualFunction.ID, new DoubleGreaterThanOrEqualFunction());
        functions.put(DoubleLessThanFunction.ID, new DoubleLessThanFunction());
        functions.put(DoubleLessThanOrEqualFunction.ID, new DoubleLessThanOrEqualFunction());
        functions.put(IntegerGreaterThanFunction.ID, new IntegerGreaterThanFunction());
        functions.put(IntegerGreaterThanOrEqualFunction.ID, new IntegerGreaterThanOrEqualFunction());
        functions.put(IntegerLessThanFunction.ID, new IntegerLessThanFunction());
        functions.put(IntegerLessThanOrEqualFunction.ID, new IntegerLessThanOrEqualFunction());

        // numeric data type conversion functions
        functions.put(DoubleToIntegerFunction.ID, new DoubleToIntegerFunction());
        functions.put(IntegerToDoubleFunction.ID, new IntegerToDoubleFunction());

        // regular expression functions
        functions.put(AnyURIRegexpMatchFunction.ID, new AnyURIRegexpMatchFunction());
        functions.put(DNSNameRegexpMatchFunction.ID, new DNSNameRegexpMatchFunction());
        functions.put(IPAddressRegexpMatchFunction.ID, new IPAddressRegexpMatchFunction());
        functions.put(RFC822NameRegexpMatchFunction.ID, new RFC822NameRegexpMatchFunction());
        functions.put(StringRegexpMatchFunction.ID, new StringRegexpMatchFunction());
        functions.put(X500NameRegexpMatchFunction.ID, new X500NameRegexpMatchFunction());
        functions.put(AuthorizationProfileConstants.ID_ALGORITHM_FQAN_REGEXP_MATCH, new FQANRegexpFunction());

        // set functions
        functions.put(AnyURIAtLeastOneMemberOfFunction.ID, new AnyURIAtLeastOneMemberOfFunction());
        functions.put(AnyURIIntersectionFunction.ID, new AnyURIIntersectionFunction());
        functions.put(AnyURISetEqualsFunction.ID, new AnyURISetEqualsFunction());
        functions.put(AnyURISubsetFunction.ID, new AnyURISubsetFunction());
        functions.put(AnyURIUnionFunction.ID, new AnyURIUnionFunction());
        functions.put(Base64BinaryAtLeastOneMemberOfFunction.ID, new Base64BinaryAtLeastOneMemberOfFunction());
        functions.put(Base64BinaryIntersectionFunction.ID, new Base64BinaryIntersectionFunction());
        functions.put(Base64BinarySetEqualsFunction.ID, new Base64BinarySetEqualsFunction());
        functions.put(Base64BinarySubsetFunction.ID, new Base64BinarySubsetFunction());
        functions.put(Base64BinaryUnionFunction.ID, new Base64BinaryUnionFunction());
        functions.put(BooleanAtLeastOneMemberOfFunction.ID, new BooleanAtLeastOneMemberOfFunction());
        functions.put(BooleanIntersectionFunction.ID, new BooleanIntersectionFunction());
        functions.put(BooleanSetEqualsFunction.ID, new BooleanSetEqualsFunction());
        functions.put(BooleanSubsetFunction.ID, new BooleanSubsetFunction());
        functions.put(BooleanUnionFunction.ID, new BooleanUnionFunction());
        functions.put(DateAtLeastOneMemberOfFunction.ID, new DateAtLeastOneMemberOfFunction());
        functions.put(DateIntersectionFunction.ID, new DateIntersectionFunction());
        functions.put(DateSetEqualsFunction.ID, new DateSetEqualsFunction());
        functions.put(DateSubsetFunction.ID, new DateSubsetFunction());
        functions.put(DateUnionFunction.ID, new DateUnionFunction());
        functions.put(DateTimeAtLeastOneMemberOfFunction.ID, new DateTimeAtLeastOneMemberOfFunction());
        functions.put(DateTimeIntersectionFunction.ID, new DateTimeIntersectionFunction());
        functions.put(DateTimeSetEqualsFunction.ID, new DateTimeSetEqualsFunction());
        functions.put(DateTimeSubsetFunction.ID, new DateTimeSubsetFunction());
        functions.put(DateTimeUnionFunction.ID, new DateTimeUnionFunction());
        functions.put(DayTimeDurationAtLeastOneMemberOfFunction.ID, new DayTimeDurationAtLeastOneMemberOfFunction());
        functions.put(DayTimeDurationIntersectionFunction.ID, new DayTimeDurationIntersectionFunction());
        functions.put(DayTimeDurationSetEqualsFunction.ID, new DayTimeDurationSetEqualsFunction());
        functions.put(DayTimeDurationSubsetFunction.ID, new DayTimeDurationSubsetFunction());
        functions.put(DayTimeDurationUnionFunction.ID, new DayTimeDurationUnionFunction());
        functions.put(DoubleAtLeastOneMemberOfFunction.ID, new DoubleAtLeastOneMemberOfFunction());
        functions.put(DoubleIntersectionFunction.ID, new DoubleIntersectionFunction());
        functions.put(DoubleSetEqualsFunction.ID, new DoubleSetEqualsFunction());
        functions.put(DoubleSubsetFunction.ID, new DoubleSubsetFunction());
        functions.put(DoubleUnionFunction.ID, new DoubleUnionFunction());
        functions.put(HexBinaryAtLeastOneMemberOfFunction.ID, new HexBinaryAtLeastOneMemberOfFunction());
        functions.put(HexBinaryIntersectionFunction.ID, new HexBinaryIntersectionFunction());
        functions.put(HexBinarySetEqualsFunction.ID, new HexBinarySetEqualsFunction());
        functions.put(HexBinarySubsetFunction.ID, new HexBinarySubsetFunction());
        functions.put(HexBinaryUnionFunction.ID, new HexBinaryUnionFunction());
        functions.put(IntegerAtLeastOneMemberOfFunction.ID, new IntegerAtLeastOneMemberOfFunction());
        functions.put(IntegerIntersectionFunction.ID, new IntegerIntersectionFunction());
        functions.put(IntegerSetEqualsFunction.ID, new IntegerSetEqualsFunction());
        functions.put(IntegerSubsetFunction.ID, new IntegerSubsetFunction());
        functions.put(IntegerUnionFunction.ID, new IntegerUnionFunction());
        functions.put(RFC822NameAtLeastOneMemberOfFunction.ID, new RFC822NameAtLeastOneMemberOfFunction());
        functions.put(RFC822NameIntersectionFunction.ID, new RFC822NameIntersectionFunction());
        functions.put(RFC822NameSetEqualsFunction.ID, new RFC822NameSetEqualsFunction());
        functions.put(RFC822NameSubsetFunction.ID, new RFC822NameSubsetFunction());
        functions.put(RFC822NameUnionFunction.ID, new RFC822NameUnionFunction());
        functions.put(StringAtLeastOneMemberOfFunction.ID, new StringAtLeastOneMemberOfFunction());
        functions.put(StringIntersectionFunction.ID, new StringIntersectionFunction());
        functions.put(StringSetEqualsFunction.ID, new StringSetEqualsFunction());
        functions.put(StringSubsetFunction.ID, new StringSubsetFunction());
        functions.put(StringUnionFunction.ID, new StringUnionFunction());
        functions.put(TimeAtLeastOneMemberOfFunction.ID, new TimeAtLeastOneMemberOfFunction());
        functions.put(TimeIntersectionFunction.ID, new TimeIntersectionFunction());
        functions.put(TimeSetEqualsFunction.ID, new TimeSetEqualsFunction());
        functions.put(TimeSubsetFunction.ID, new TimeSubsetFunction());
        functions.put(TimeUnionFunction.ID, new TimeUnionFunction());
        functions.put(X500NameAtLeastOneMemberOfFunction.ID, new X500NameAtLeastOneMemberOfFunction());
        functions.put(X500NameIntersectionFunction.ID, new X500NameIntersectionFunction());
        functions.put(X500NameSetEqualsFunction.ID, new X500NameSetEqualsFunction());
        functions.put(X500NameSubsetFunction.ID, new X500NameSubsetFunction());
        functions.put(X500NameUnionFunction.ID, new X500NameUnionFunction());
        functions
                .put(YearMonthDurationAtLeastOneMemberOfFunction.ID, new YearMonthDurationAtLeastOneMemberOfFunction());
        functions.put(YearMonthDurationIntersectionFunction.ID, new YearMonthDurationIntersectionFunction());
        functions.put(YearMonthDurationSetEqualsFunction.ID, new YearMonthDurationSetEqualsFunction());
        functions.put(YearMonthDurationSubsetFunction.ID, new YearMonthDurationSubsetFunction());
        functions.put(YearMonthDurationUnionFunction.ID, new YearMonthDurationUnionFunction());

        // special matching functions
        functions.put(RFC822NameMatchFunction.ID, new RFC822NameMatchFunction());
        functions.put(X500NameMatchFunction.ID, new X500NameMatchFunction());

        // string conversion functions
        functions.put(StringNormalizeSpaceFunction.ID, new StringNormalizeSpaceFunction());
        functions.put(StringNormalizeToLowerCaseFunction.ID, new StringNormalizeToLowerCaseFunction());

        // string functions
        functions.put(StringConcatenateFunction.ID, new StringConcatenateFunction());
        functions.put(UriStringConcatenateFunction.ID, new UriStringConcatenateFunction());

        URNToFunctionConverter.setFunctions(functions);
    }

    /** Initialize all the standard policy combining types. */
    private static void initializePolicyCombiningAlgorithms() {
        HashMap<String, PolicyCombiningAlgorithm> algos = new HashMap<String, PolicyCombiningAlgorithm>();
        algos.put(PolicyDenyOverridesAlgorithm.ID, new PolicyDenyOverridesAlgorithm());
        algos.put(PolicyFirstApplicableAlgorithm.ID, new PolicyFirstApplicableAlgorithm());
        algos.put(PolicyOnlyOneApplicableAlgorithm.ID, new PolicyOnlyOneApplicableAlgorithm());
        algos.put(PolicyOrderedDenyOverridesAlgorithm.ID, new PolicyOrderedDenyOverridesAlgorithm());
        algos.put(PolicyOrderedPermitOverridesAlgorithm.ID, new PolicyOrderedPermitOverridesAlgorithm());
        algos.put(PolicyPermitOverridesAlgorithm.ID, new PolicyPermitOverridesAlgorithm());

        URNToPolicyCombiningAlgorithmConverter.setCombiningAlgorithms(algos);
    }

    /** Initialize all the standard rule combining types. */
    private static void initializeRuleCombiningAlgorithms() {
        HashMap<String, RuleCombiningAlgorithm> algos = new HashMap<String, RuleCombiningAlgorithm>();
        algos.put(RuleDenyOverridesAlgorithm.ID, new RuleDenyOverridesAlgorithm());
        algos.put(RuleFirstApplicableAlgorithm.ID, new RuleFirstApplicableAlgorithm());
        algos.put(RuleOrderedDenyOverridesAlgorithm.ID, new RuleOrderedDenyOverridesAlgorithm());
        algos.put(RuleOrderedPermitOverridesAlgorithm.ID, new RuleOrderedPermitOverridesAlgorithm());
        algos.put(RulePermitOverridesAlgorithm.ID, new RulePermitOverridesAlgorithm());
        
        URNToRuleCombiningAlgorithmConverter.setCombiningAlgorithms(algos);
    }
}