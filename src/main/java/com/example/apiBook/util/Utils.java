package com.example.apiBook.util;

import org.apache.http.client.utils.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

public class Utils {

    static final Logger logger = LoggerFactory.getLogger(Utils.class);
    public static Date getEndTime(Date startTime, int warranty) {
        Calendar c = Calendar.getInstance();
        c.setTime(startTime);
        c.add(Calendar.YEAR, warranty);
        return c.getTime();
    }

    public static String getProperty(Object object) {

        return object != null ? object.toString() : null;
    }

    public static Integer parserInteger(String object) {
        Integer props = 0;
        try {
            if(object != null && isNumeric(object)){
                props = Integer.parseInt(object);
            }
        }catch(Exception e){
            return 0;
        }
        return props;
    }

    public static Date parserDate(String date, String[] patterns){
        return DateUtils.parseDate(date, patterns);
    }

//    public static Date parserDate(String dateString, String pattern) {
//        if(StringUtils.isEmpty(dateString)){
//            return null;
//        }
//        DateTimeFormatter dateTimeFormatter = DateTimeFormat.forPattern(pattern);
//        try {
//            DateTime result = dateTimeFormatter.parseDateTime(dateString);
//            String value = dateTimeFormatter.print(result);
//            if(value.equals(dateString)){
//                return result.toDate();
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return null;
//    }

    public static Date reformatDate(Object dateString, String pattern) {
    	SimpleDateFormat fm = new SimpleDateFormat(pattern);
        try {
            return fm.parse(fm.format(dateString));
        } catch (ParseException e) {
        	e.printStackTrace();
        }
        return null;
    }

    public static Date dateFrom(String dateString, String pattern) {
    	SimpleDateFormat fm = new SimpleDateFormat(pattern);
        try {
            return fm.parse(dateString);
        } catch (ParseException e) {
        	e.printStackTrace();
        }
        return null;
    }
//    public static Date getDate(Object object, String pattern) {
//        return dateFrom(object, pattern);
//    }
    public static String dateToString(Date date, String pattern){
    	SimpleDateFormat fm = new SimpleDateFormat(pattern);
        try {
            return fm.format(date);
        }catch (Exception e){
            return "";
        }
    }
//    public static String converDateToString(Date date, String pattern) {
//        return  dateToString(date, pattern);
//    }
    public static boolean checkIsDuplicate(List<String> list){
        Set<String> store = new HashSet<>();
        for (String e: list) {
            if (store.add(e) == false) return true;
        }
        return false;
    }

    public static int compareDate(String time1, String time2) {
        SimpleDateFormat sf = new SimpleDateFormat("yyyy-MM-dd");
        Date d1 = null;
        Date d2 = null;
        try {
            d1 = sf.parse(time1);
            d2 = sf.parse(time2);
        } catch (ParseException e) {
            // TODO Auto-generated catch block
//            logger.error("fail date" + e.toString());
        }
        if (d1.compareTo(d2) < 0)
            return -1;
        else if (d1.compareTo(d2) > 0)
            return 1;
        else return 0;
    }
    public static String getURIPath(String scheme, String host, int port, String path, String urlPath, String query){
        try {
            URI uri = new URI(scheme, null, host, port, path, null, null);
            uri = UriComponentsBuilder.fromUri(uri).path(urlPath).query(query).build(true).toUri();
            return uri.toString();
        } catch (URISyntaxException e){
            return "";
        }

    }

    public static Date getPreYear() {
    	Calendar cal = Calendar.getInstance();
		cal.add(Calendar.YEAR, -1);
		Date preYear = cal.getTime();

		return preYear;
    }

   /* public static String getCellValue(Workbook workbook, Row row, int cellNum) {
        String object = "";
        FormulaEvaluator evaluator = workbook.getCreationHelper().createFormulaEvaluator();
        if (row != null) {
            Cell cell = row.getCell(cellNum);
            if (cell != null) {
                if (cell.getCellType() == CellType.FORMULA) {
                    switch (evaluator.evaluateFormulaCell(cell)) {
                        case BOOLEAN:
                            object = String.valueOf(cell.getBooleanCellValue());
                            break;
                        case NUMERIC:
                            object = String.format("%.0f", cell.getNumericCellValue());
                            break;
                        case STRING:
                            object = cell.getStringCellValue();
                            break;
                    }
                } else if (cell.getCellType() == CellType.STRING) {
                    object = cell.getStringCellValue();
                } else if (cell.getCellType() == CellType.NUMERIC) {
                    object = String.format("%.0f", cell.getNumericCellValue());
                } else if (cell.getCellType() == CellType.BOOLEAN) {
                    object = String.valueOf(cell.getBooleanCellValue());
                }
            }
        }
        return object.trim();
    }*/
 /*   public static Date getExcelDateFromString(String date, TimeZone timeZone){
        try {
            return DateUtil.getJavaDate(Double.valueOf(date), timeZone);
        }catch (Exception e){
            return null;
        }

    }
    // slurp content from given input and close it
    public static boolean isExcelFile(InputStream in) throws IOException {
        try {
            // it slurp the input stream
            Workbook workbook = org.apache.poi.ss.usermodel.WorkbookFactory.create(in);
            workbook.close();
            return true;

        } catch (IllegalArgumentException e) {
            return false;
        }
    }
    public static Workbook getWorkbook(MultipartFile file) {
        Workbook workbook = null;
        try {
            workbook = new XSSFWorkbook(file.getInputStream());
        } catch (Exception e){
            logger.info("error===>{}", e.getMessage());
            try {
                // HSSFWorkbook, InputStream, needs more memory
                POIFSFileSystem fs = new POIFSFileSystem(file.getInputStream());
                workbook = new HSSFWorkbook(fs.getRoot(), true);
            } catch (Exception e1){
                logger.info("error1===>{}", e1.getMessage());
            }
        }
        return workbook;
    }*/
    public static String getProvinceFromText(String text, List<String> provinces){
        if (StringUtils.isEmpty(text)) return null;
        String province = null;
        for (String p: provinces) {
            if (p != null && text.toLowerCase().indexOf(p.toLowerCase()) > -1){
                province = p;
            }
        }
        return province;
    }

    public static Date getDateWithoutTimeUsingCalendar() {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 0);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);

        return calendar.getTime();
    }

    public static boolean isNumeric(String strNum) {
        Pattern pattern = Pattern.compile("-?\\d+(\\.\\d+)?");
        if (strNum == null) {
            return false;
        }
        return pattern.matcher(strNum).matches();
    }
    public static String getClientIp(HttpServletRequest request) {

        String remoteAddr = "";
        if (request != null) {
            remoteAddr = request.getHeader("X-FORWARDED-FOR");
            if (remoteAddr == null || "".equals(remoteAddr)) {
                remoteAddr = request.getRemoteAddr();
            }
        }
        return remoteAddr;
    }

    public static Date getPreviousDate(Date fromDate) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(fromDate);
        calendar.add(Calendar.DATE, -1);
        Date previousDate = calendar.getTime();
        return previousDate;
    }

    public static Date getNextDate(Date fromDate) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(fromDate);
        calendar.add(Calendar.DATE, 1);
        Date previousDate = calendar.getTime();
        return previousDate;
    }

    public static Date addedDate(Date fromDate, int amount) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(fromDate);
        calendar.add(Calendar.DATE, amount);
        Date previousDate = calendar.getTime();
        return previousDate;
    }
}
