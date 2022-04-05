/*
 * Copyright 2021 NetKnights GmbH - nils.behlen@netknights.it
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TestRollout
{
    private PrivacyIDEA privacyIDEA;
    private ClientAndServer mockServer;

    @Before
    public void setup()
    {
        mockServer = ClientAndServer.startClientAndServer(1080);

        privacyIDEA = PrivacyIDEA.newBuilder("https://127.0.0.1:1080", "test").sslVerify(false)
                                 .serviceAccount("admin", "admin").logger(new PILogImplementation()).build();
    }

    @Test
    public void test()
    {
        String authToken =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU" +
                "4ZDVhODY5YzUzNGI5ZmY1MWFmNzI2ZjI5OTE2YmYiLCJyb2xlIjoiYWRtaW4iLCJhdXRodHlwZSI6InBhc3N3b3JkIiwiZXhwIjoxNTg5NDUwMzk0LC" +
                "JyaWdodHMiOlsicG9saWN5ZGVsZXRlIiwic3RhdGlzdGljc19yZWFkIiwiYXVkaXRsb2ciLCJlbmFibGUiLCJ1c2VybGlzdCIsInVwZGF0ZXVzZXIiL" +
                "CJhZGR1c2VyIiwiZW5yb2xsU1BBU1MiLCJjYWNvbm5lY3RvcndyaXRlIiwidW5hc3NpZ24iLCJkZWxldGV1c2VyIiwic2V0cGluIiwiZGlzYWJsZSIs" +
                "ImVucm9sbFNTSEtFWSIsImZldGNoX2F1dGhlbnRpY2F0aW9uX2l0ZW1zIiwicHJpdmFjeWlkZWFzZXJ2ZXJfcmVhZCIsImdldHJhbmRvbSIsImVucm9" +
                "sbFNNUyIsIm1yZXNvbHZlcndyaXRlIiwicmFkaXVzc2VydmVyX3dyaXRlIiwiaW1wb3J0dG9rZW5zIiwic2V0X2hzbV9wYXNzd29yZCIsImVucm9sbF" +
                "JFTU9URSIsImVucm9sbFUyRiIsInByaXZhY3lpZGVhc2VydmVyX3dyaXRlIiwiZW5yb2xsUkFESVVTIiwiY29weXRva2VucGluIiwiZW5yb2xsRU1BS" +
                "UwiLCJyZXNldCIsImNhY29ubmVjdG9yZGVsZXRlIiwiZW5yb2xsVkFTQ08iLCJlbnJvbGxSRUdJU1RSQVRJT04iLCJzZXQiLCJnZXRzZXJpYWwiLCJw" +
                "ZXJpb2RpY3Rhc2tfcmVhZCIsImV2ZW50aGFuZGxpbmdfd3JpdGUiLCJtcmVzb2x2ZXJkZWxldGUiLCJyZXNvbHZlcmRlbGV0ZSIsInNtdHBzZXJ2ZXJ" +
                "fd3JpdGUiLCJyYWRpdXNzZXJ2ZXJfcmVhZCIsImVucm9sbDRFWUVTIiwiZW5yb2xsUEFQRVIiLCJlbnJvbGxZVUJJQ08iLCJnZXRjaGFsbGVuZ2VzIi" +
                "wibWFuYWdlc3Vic2NyaXB0aW9uIiwibG9zdHRva2VuIiwiZGVsZXRlIiwiZW5yb2xscGluIiwic21zZ2F0ZXdheV93cml0ZSIsImVucm9sbFBVU0giL" +
                "CJlbnJvbGxNT1RQIiwibWFuYWdlX21hY2hpbmVfdG9rZW5zIiwic3lzdGVtX2RvY3VtZW50YXRpb24iLCJtYWNoaW5lbGlzdCIsInRyaWdnZXJjaGFs" +
                "bGVuZ2UiLCJzdGF0aXN0aWNzX2RlbGV0ZSIsInJlc29sdmVyd3JpdGUiLCJjbGllbnR0eXBlIiwic2V0dG9rZW5pbmZvIiwiZW5yb2xsT0NSQSIsImF" +
                "1ZGl0bG9nX2Rvd25sb2FkIiwiZW5yb2xsUFciLCJlbnJvbGxIT1RQIiwiZW5yb2xsVEFOIiwiZXZlbnRoYW5kbGluZ19yZWFkIiwiY29weXRva2VudX" +
                "NlciIsInRva2VubGlzdCIsInNtdHBzZXJ2ZXJfcmVhZCIsImVucm9sbERBUExVRyIsInJldm9rZSIsImVucm9sbFRPVFAiLCJjb25maWdyZWFkIiwiY" +
                "29uZmlnd3JpdGUiLCJzbXNnYXRld2F5X3JlYWQiLCJlbnJvbGxRVUVTVElPTiIsInRva2VucmVhbG1zIiwiZW5yb2xsVElRUiIsInBvbGljeXJlYWQi" +
                "LCJtcmVzb2x2ZXJyZWFkIiwicGVyaW9kaWN0YXNrX3dyaXRlIiwicG9saWN5d3JpdGUiLCJyZXNvbHZlcnJlYWQiLCJlbnJvbGxDRVJUSUZJQ0FURSI" +
                "sImFzc2lnbiIsImNvbmZpZ2RlbGV0ZSIsImVucm9sbFlVQklLRVkiLCJyZXN5bmMiXX0.HvP_hgA-UJFINXnwoBVmAurqcaaMmwM-AsD1S6chGIM";

        String img =
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAeoAAAHqAQAAAADjFjCXAAAEH0lEQVR4nO2dQY6kOgyGfz+QahmkOUAfBW426iO9" +
                "G8BR6gAjwbKkoP8tnJDQM6uCVk09fi9QU9SnFJJlx3bsNuKATP8coQHhwoULFy5cuHDh5+KWpIWZtQAWM7NuNRsWMxuwGqYO8FszMxvOW1341XCQJNG" +
                "TJOeGLmOIAEK6A0JEepq/4sT41u8u/NX4spkvADagITkDmKwFRzQ06/JTN4dnri782rgNSwuOWA2TmQFY/UIyfvvqwi+KTx8PQ3+/Ef3cuHMFlhvTvu" +
                "6bVxd+CTz7ykAAS7ox1zWshn4G/S+EtSUWoM4rv/W7C38xPpmZ79zczN1b2ICGwNLCfs4N0d9vtAGrh7Cnri78Yji4FwCbX3VpSDJ6SJFi3U0Uwwp/S" +
                "koeBP0MIKkZ6WqGEFEeJCYocyL8DHxp4Wk5T9UtZkB4GHm/kZ8dsuq5Eq7ysMKPSDJsJQXskStzDAvAM3cIJEcAfpGHFX4cX82GEGH28bCkZliNI1K+" +
                "hKPbvwggRP/sr/nxwt8LR4khyBkeNKTIId8W0+dfIaNsnfAjUkekW/V13CKHLcxIrrd8Jq0T/rTkeBVwazYCqPd1YVPKsusDIK0TfkB2+bdytATI51B" +
                "yNFE87BjkYYUfkpyvywqXksERWcOKw22YFS7K1gk/ImVLV6mUp+U8zADS+bpyC0jrhB+RpE0hB7JjuYTkdXe1iWTwpHXCD0i2ddwSJHW8mrxuyE54zK" +
                "eKpXXCD0i2dRE5kM1a11f1ilyRSJ54y7W89bsLfzHez0C2ZqQNpQQRHrnmGkj7eb+5EbThxNWFXwzf27qm9rX7fHH2tSmRLA8r/IBUqTpXONTeFFupD" +
                "OXgXV96yd763YW/Cs/5ujklg3e9h7HayOX0SdzV0N763YW/Ct9VxLLVS3WwKqQA6gLZDGVOhJ+AB6YeCbMb/VTn1AEcw8OPQPHzI4W5KdY4c3Xh18Kr" +
                "k065IrHbuX1xqVv6Th5W+AHJ+7pdRWLcuiX6vOv72qgjrRP+tGyzI1Yjwq/U9trPIKaP2BJLByDElpM10RB+OcFTVhd+TXzrm0Cdr/MzJ388h5KO4Mn" +
                "WCT+OZ10DfMRJ64N1cpUiFSjSiJ1A2nDm6sKvhbu/NKCJBjQRHlcsHayff0RM3QxgudEma2jV7IkzVhd+Tfy33v+eWzEssBqxk10v6wEA8rDCn5KcOQ" +
                "FQuvtLqWKsThBnJSyqJ60TfgDvt5CihA++fQsPc12bLI0HSIMCTlxd+MXwqg5bedNU89p6JLbOsCSq/gs/EyfvN5p1eYhYGd257fU4qvdf+DfgqVEC4" +
                "GeXRhKnRlkXTdcRfkR+n9UZHsbp42EEYnra/9vBENYW/d3A/q59nfBD8jWG9fCVsQpfq0TKlk3Wvk7482L673XChQsXLly4cOH/C/w/XCJfutUMsSMA" +
                "AAAASUVORK5CYII=";

        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_AUTH).withMethod("POST").withBody(""))
                  .respond(HttpResponse.response()
                                       // This response is simplified because it is very long and contains info that is not (yet) processed anyway
                                       .withBody("{\n" + "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" +
                                                 "    \"result\": {\n" + "        \"status\": true,\n" +
                                                 "        \"value\": {\n" + "            \"log_level\": 20,\n" +
                                                 "            \"menus\": [\n" + "                \"components\",\n" +
                                                 "                \"machines\"\n" + "            ],\n" +
                                                 "            \"realm\": \"\",\n" + "            \"rights\": [\n" +
                                                 "                \"policydelete\",\n" +
                                                 "                \"resync\"\n" + "            ],\n" +
                                                 "            \"role\": \"admin\",\n" + "            \"token\": \"" +
                                                 authToken + "\",\n" + "            \"username\": \"admin\",\n" +
                                                 "            \"logout_time\": 120,\n" +
                                                 "            \"default_tokentype\": \"hotp\",\n" +
                                                 "            \"user_details\": false,\n" +
                                                 "            \"subscription_status\": 0\n" + "        }\n" +
                                                 "    },\n" + "    \"time\": 1589446794.8502703,\n" +
                                                 "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                                 "    \"versionnumber\": \"3.2.1\",\n" +
                                                 "    \"signature\": \"rsa_sha256_pss:\"\n" + "}"));


        mockServer.when(HttpRequest.request().withPath(PIConstants.ENDPOINT_TOKEN_INIT).withMethod("POST")
                                   .withHeader(Header.header("Authorization", authToken))).respond(
                HttpResponse.response().withBody("{\n" + "    \"detail\": {\n" + "        \"googleurl\": {\n" +
                                                 "            \"description\": \"URL for google Authenticator\",\n" +
                                                 "            \"img\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAeoAAAHqAQAAAADjFjCXAAAEH0lEQVR4nO2dQY6kOgyGfz+QahmkOUAfBW426iO9G8BR6gAjwbKkoP8tnJDQM6uCVk09fi9QU9SnFJJlx3bsNuKATP8coQHhwoULFy5cuHDh5+KWpIWZtQAWM7NuNRsWMxuwGqYO8FszMxvOW1341XCQJNGTJOeGLmOIAEK6A0JEepq/4sT41u8u/NX4spkvADagITkDmKwFRzQ06/JTN4dnri782rgNSwuOWA2TmQFY/UIyfvvqwi+KTx8PQ3+/Ef3cuHMFlhvTvu6bVxd+CTz7ykAAS7ox1zWshn4G/S+EtSUWoM4rv/W7C38xPpmZ79zczN1b2ICGwNLCfs4N0d9vtAGrh7Cnri78Yji4FwCbX3VpSDJ6SJFi3U0Uwwp/SkoeBP0MIKkZ6WqGEFEeJCYocyL8DHxp4Wk5T9UtZkB4GHm/kZ8dsuq5Eq7ysMKPSDJsJQXskStzDAvAM3cIJEcAfpGHFX4cX82GEGH28bCkZliNI1K+hKPbvwggRP/sr/nxwt8LR4khyBkeNKTIId8W0+dfIaNsnfAjUkekW/V13CKHLcxIrrd8Jq0T/rTkeBVwazYCqPd1YVPKsusDIK0TfkB2+bdytATI51ByNFE87BjkYYUfkpyvywqXksERWcOKw22YFS7K1gk/ImVLV6mUp+U8zADS+bpyC0jrhB+RpE0hB7JjuYTkdXe1iWTwpHXCD0i2ddwSJHW8mrxuyE54zKeKpXXCD0i2dRE5kM1a11f1ilyRSJ54y7W89bsLfzHez0C2ZqQNpQQRHrnmGkj7eb+5EbThxNWFXwzf27qm9rX7fHH2tSmRLA8r/IBUqTpXONTeFFupDOXgXV96yd763YW/Cs/5ujklg3e9h7HayOX0SdzV0N763YW/Ct9VxLLVS3WwKqQA6gLZDGVOhJ+AB6YeCbMb/VTn1AEcw8OPQPHzI4W5KdY4c3Xh18Krk065IrHbuX1xqVv6Th5W+AHJ+7pdRWLcuiX6vOv72qgjrRP+tGyzI1Yjwq/U9trPIKaP2BJLByDElpM10RB+OcFTVhd+TXzrm0Cdr/MzJ388h5KO4MnWCT+OZ10DfMRJ64N1cpUiFSjSiJ1A2nDm6sKvhbu/NKCJBjQRHlcsHayff0RM3QxgudEma2jV7IkzVhd+Tfy33v+eWzEssBqxk10v6wEA8rDCn5KcOQFQuvtLqWKsThBnJSyqJ60TfgDvt5CihA++fQsPc12bLI0HSIMCTlxd+MXwqg5bedNU89p6JLbOsCSq/gs/EyfvN5p1eYhYGd257fU4qvdf+DfgqVEC4GeXRhKnRlkXTdcRfkR+n9UZHsbp42EEYnra/9vBENYW/d3A/q59nfBD8jWG9fCVsQpfq0TKlk3Wvk7482L673XChQsXLly4cOH/C/w/XCJfutUMsSMAAAAASUVORK5CYII=\",\n" +
                                                 "            \"value\": \"otpauth://hotp/OATH0003A0AA?secret=4DK5JEEQMWY3VES7EWB4M36TAW4YC2YH&counter=1&digits=6&issuer=privacyIDEA\"\n" +
                                                 "        },\n" + "        \"oathurl\": {\n" +
                                                 "            \"description\": \"URL for OATH token\",\n" +
                                                 "            \"img\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAeoAAAHqAQAAAADjFjCXAAAEDUlEQVR4nO2dTW6kSBCFX3Qi1RJu4KMkNxv1kfoGcBQfYCRYlgR6s8jIH9y9Kuhxu3lvUTZVfMqyFIrI+CFtxAnN387QgHDhwoULFy5cuPBrcXN1AFYzYDWzcTWzEbsBq3+Q3jMzs/G61YXfFI8kyQXAPASaDQCAQGB9EOifZiMCAQSSJI/4ydWF3wzv/Oc6APEHYHEZDABAYAPQb7D4YwCx+q0GhO2a1YULT+qz18PaAbN1wPxGYh4ATr97deG3xc3emOIqIp9Gvnewsd9g4/+wuvDb4D2ZHNk8AOS7GbA+yAmBNvZPq26O5PYRP7m68Fvis5mlHCK+d7ARgTYCsDGlrw/aP+8dAOwphb10deE3w1M20bbF+mebTcxDKInEbjze+tlfXvgXxZHqIHEBAARy6jd4NpHyipDsjBNCTjNy+YTTl/7bhX8WDjeffgOnniS5IdlaXABE+geIdTeHwFThk9UJf0ludQieTaCxsJB8XfJwcQmN6cnXCT8hj7D0inDOZkOJuvUW5ljbb7I64WdUTaraWoq1zQ4vN8NSwE2uT1Yn/FU1HTFGApzfNn8vLqABYbM4AQR242yB1uBf+m8X/lm4h8qksodDSi628ul2DLPKYYWfUlM5idzgv5UcFsn0PK7W0KsIK/yEfG6p93pJSmRjrtIhLoGpctLs64pkdcJfUrW6Gj79JYfZZHrkhmyTqpwIPyW3unq51EDK4uZqNVn7OuEX4d7uSl6PzD1/n2WvtWEb4fW6K1cXfje8jbAAckqRN26pVQG4/6v7P2UTwl9XmTnZQWDvCARiHv7tOI8AsFoeM1kNxPqgxempSSfhZ9T0Jj60W5va3AKg2c1pXyf8nBpD8tGSYoQlzYh5DoUs/VpFWOGvq+amOX3dynxT7cPmhKO8J18n/ITYqsw3lS4F6uDdghJ/qWxC+BnlCJsvp/zixnXoUtSJKPk64afxWMsnuRkBYDd/ZCxf8rv5c2OXri78ZnjT/XdrSh2JQzNswi/yWvk64S+rFoNdpeeahgFKvppyDaAtJMvqhL+kWq/LXf0t56vZ9aUbY7ZJ7euEXxhhmV0a0lTTIbg2z41VxyirE/6SstW1Y5y5LZurJO7wSg4hqxN+TjwKxbhYJ4h9r8fWCLWvE34Sr2d1ckonTviBiTYiEPPbM59usvphJ17h+xO+vPAvhx+7/4fKSav2eURFWOEX4Ws5ahh78XXu/8yGQMxDIObG4V24uvB74d1P76wPAtg7oN+69BQsVgPQL+VAp90QpwtWFy4cAOrpTmhOwy5K59ylttjvWF34LfCP+7p8WY89yYNPPlrH9vFE7euEv6RcLwHQFE0WoBne9GZYbpCpDyv8HG7673XChQsXLly4cOF/Bf4fmxJSuTwnV0oAAAAASUVORK5CYII=\",\n" +
                                                 "            \"value\": \"oathtoken:///addToken?name=OATH0003A0AA&lockdown=true&key=e0d5d4909065b1ba925f2583c66fd305b9816b07\"\n" +
                                                 "        },\n" + "        \"otpkey\": {\n" +
                                                 "            \"description\": \"OTP seed\",\n" +
                                                 "            \"img\": \"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAXIAAAFyAQAAAADAX2ykAAACZklEQVR4nO2bTYrcMBCFX0UGL2XIgeQb5Eh9NfsoPsCAtDTIvCwk2ZrpCZ0JHseCqkWD5W9RUNTPK7mF+IrNP76EA8orr7zyyiuv/J94ydaV49AB87AJEMq78UJ/lD+ZdyRJD2AeAJFhE3ksPWWEIUnyPf/d/ih/Mh9yhsqITeAYwakwdWLf1X/lP7fu6SR0wCyAAOZ6f5T/Zt55lHLNVY4k/l/+KH8Kb8kSS8M0Ws3Sp65LMl7tj/Kn8rOIiAzl1C095eFzOxYRkWv9Uf4kPvXfeklpVwHsKgRW4ft39/Nf+ReWxI/zAABDTpYE9p/jBUlyupv/yr+wQ9xysnEPt0lyOPdkS6aZS+PbGF/0kfUQt3QQ2LcuF2mYiPSIreM1/ih/Lp/77zx2kUDsiFCmZmATfFTId/Nf+b/j7SpA6JCG6HkwFJGeuWYvve4n2+SRBydGJBGczJt85rwhYCO0/zbJ5/hOMGlWJr3Zx608RFem8W2ML/nry5rKHfnrDeHSWYTGt0m+xM1mVVS0UETO6XKTpPFtki/61+YgH49VkFX/Nss/769QbzVyYmt9bp43hOMqOdI2Am6RpJnS24v9Uf4UvuRvqcXHJJ2X0Ml0/9wov+vfvfWinqnh9uqt/bdFvrpfAI78ZUzXDcdMrfnbMu9KwsrDb7nruqUvqyu/6f1+m3w9P9e7yLyurECtzy3yz99PAgDCTwJBwHw1uBXubv4r/y/8PGwio2W6RJIRuyZuw3/li+33+wQQ0tdWxPzLAwgDAPsmNX83/5V/YR/m50oQVapX9W+rvOj/u5VXXnnllVf+cv436kn2XK+E3tcAAAAASUVORK5CYII=\",\n" +
                                                 "            \"value\": \"seed://e0d5d4909065b1ba925f2583c66fd305b9816b07\",\n" +
                                                 "            \"value_b32\": \"4DK5JEEQMWY3VES7EWB4M36TAW4YC2YH\"\n" +
                                                 "        },\n" + "        \"rollout_state\": \"\",\n" +
                                                 "        \"serial\": \"OATH0003A0AA\",\n" +
                                                 "        \"threadid\": 140470638720768\n" + "    },\n" +
                                                 "    \"id\": 1,\n" + "    \"jsonrpc\": \"2.0\",\n" +
                                                 "    \"result\": {\n" + "        \"status\": true,\n" +
                                                 "        \"value\": true\n" + "    },\n" +
                                                 "    \"time\": 1592834605.532012,\n" +
                                                 "    \"version\": \"privacyIDEA 3.3.3\",\n" +
                                                 "    \"versionnumber\": \"3.3.3\",\n" +
                                                 "    \"signature\": \"rsa_sha256_pss:\"\n" + "}"));

        RolloutInfo rolloutInfo = privacyIDEA.tokenRollout("games", "hotp");

        assertEquals(img, rolloutInfo.googleurl.img);
        assertNotNull(rolloutInfo.googleurl.description);
        assertNotNull(rolloutInfo.googleurl.value);

        assertNotNull(rolloutInfo.otpkey.description);
        assertNotNull(rolloutInfo.otpkey.value);
        assertNotNull(rolloutInfo.otpkey.img);
        assertNotNull(rolloutInfo.otpkey.value_b32);

        assertNotNull(rolloutInfo.oathurl.value);
        assertNotNull(rolloutInfo.oathurl.description);
        assertNotNull(rolloutInfo.oathurl.img);

        assertNotNull(rolloutInfo.serial);
        assertTrue(rolloutInfo.rolloutState.isEmpty());
    }

    @After
    public void teardown()
    {
        mockServer.stop();
    }
}
