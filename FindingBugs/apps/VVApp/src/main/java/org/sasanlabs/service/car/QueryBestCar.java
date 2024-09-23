package org.sasanlabs.service.car;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import org.sasanlabs.internal.utility.LevelConstants;
import org.sasanlabs.internal.utility.Variant;
import org.sasanlabs.internal.utility.annotations.AttackVector;
import org.sasanlabs.internal.utility.annotations.VulnerableAppRequestMapping;
import org.sasanlabs.internal.utility.annotations.VulnerableAppRestController;
import org.sasanlabs.vulnerability.types.VulnerabilityType;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Nothing to say
 *
 * @author preetkaran20@gmail.com KSASAN
 */
public class QueryBestCar {

    private final JdbcTemplate applicationJdbcTemplate;

    public QueryBestCar(
            @Qualifier("applicationJdbcTemplate") final JdbcTemplate applicationJdbcTemplate) {
        this.applicationJdbcTemplate = applicationJdbcTemplate;
    }

    public ResponseEntity<CarInformation> getCarInformationLevel1(
            @RequestParam final Map<String, String> queryParams) {
        return applicationJdbcTemplate.query(
                "select * from cars where id=" + queryParams.get("id"), this::resultSetToResponse);
    }

    public ResponseEntity<CarInformation> getCarInformationLevel2(
            @RequestParam final Map<String, String> queryParams) {
        final String model = ("\\'" + queryParams.get("model").replaceAll("\\", "") + "\\'");
        return applicationJdbcTemplate.query(
                "select * from cars where model='" + model + "'", this::resultSetToResponse);
    }

    public ResponseEntity<CarInformation> getCarInformationLevel3(
            @RequestParam final Map<String, String> queryParams) {
        final String np = queryParams.get("numberPlate").replaceAll("'", "");
        return applicationJdbcTemplate.query(
                "select * from cars where np='" + np + "'", this::resultSetToResponse);
    }

    public ResponseEntity<CarInformation> getCarInformationLevel4(
            @RequestParam final Map<String, String> queryParams) {
        final String id = queryParams.get("id");

        return applicationJdbcTemplate.query(
                "select * from cars where id=?",
                prepareStatement -> prepareStatement.setString(1, id),
                this::resultSetToResponse);
    }

    private ResponseEntity<CarInformation> resultSetToResponse(final ResultSet rs)
            throws SQLException {
        final CarInformation carInformation = new CarInformation();
        if (rs.next()) {
            carInformation.setId(rs.getInt(1));
            carInformation.setName(rs.getString(2));
            carInformation.setImagePath(rs.getString(3));
        }
        return new ResponseEntity<>(carInformation, HttpStatus.OK);
    }
}
