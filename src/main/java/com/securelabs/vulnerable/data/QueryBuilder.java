package com.securelabs.vulnerable.data;

import java.util.*;

/**
 * VULNERABLE: Query Builder
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A03: SQL Injection through dynamic query construction
 * - No input validation or sanitization
 */
public class QueryBuilder {

    private StringBuilder query;
    private String table;
    private List<String> conditions;
    private String orderBy;
    private Integer limit;

    public QueryBuilder() {
        this.conditions = new ArrayList<>();
    }

    /**
     * VULNERABLE: Table name is not validated
     */
    public QueryBuilder from(String table) {
        // VULNERABLE: No validation of table name
        this.table = table;
        return this;
    }

    /**
     * VULNERABLE: Direct string concatenation for WHERE clause
     */
    public QueryBuilder where(String field, String operator, String value) {
        // VULNERABLE: All parameters are directly concatenated
        String condition = field + " " + operator + " '" + value + "'";
        conditions.add(condition);
        return this;
    }

    /**
     * VULNERABLE: Raw WHERE clause injection
     */
    public QueryBuilder whereRaw(String rawCondition) {
        // VULNERABLE: Allows arbitrary SQL in WHERE clause
        conditions.add(rawCondition);
        return this;
    }

    /**
     * VULNERABLE: Unvalidated ORDER BY clause
     */
    public QueryBuilder orderBy(String column, String direction) {
        // VULNERABLE: Column and direction are not validated
        this.orderBy = column + " " + direction;
        return this;
    }

    /**
     * VULNERABLE: LIMIT with string concatenation
     */
    public QueryBuilder limit(String limit) {
        // VULNERABLE: Limit is parsed from string without validation
        try {
            this.limit = Integer.parseInt(limit);
        } catch (NumberFormatException e) {
            // VULNERABLE: Silent failure, could use default or inject
            this.limit = 100;
        }
        return this;
    }

    /**
     * VULNERABLE: Build query with string concatenation
     */
    public String build() {
        StringBuilder sql = new StringBuilder();
        sql.append("SELECT * FROM ").append(table);

        if (!conditions.isEmpty()) {
            sql.append(" WHERE ");
            sql.append(String.join(" AND ", conditions));
        }

        if (orderBy != null) {
            sql.append(" ORDER BY ").append(orderBy);
        }

        if (limit != null) {
            sql.append(" LIMIT ").append(limit);
        }

        // VULNERABLE: Logging full query with potentially sensitive data
        System.out.println("Built query: " + sql.toString());

        return sql.toString();
    }

    /**
     * VULNERABLE: Dynamic field selection
     */
    public String buildSelect(List<String> fields) {
        // VULNERABLE: Fields are not validated
        String fieldList = String.join(", ", fields);

        StringBuilder sql = new StringBuilder();
        sql.append("SELECT ").append(fieldList).append(" FROM ").append(table);

        if (!conditions.isEmpty()) {
            sql.append(" WHERE ");
            sql.append(String.join(" AND ", conditions));
        }

        return sql.toString();
    }

    /**
     * VULNERABLE: INSERT query builder with injection
     */
    public String buildInsert(Map<String, String> values) {
        StringBuilder sql = new StringBuilder();
        sql.append("INSERT INTO ").append(table).append(" (");

        // VULNERABLE: Column names from user input
        sql.append(String.join(", ", values.keySet()));
        sql.append(") VALUES ('");

        // VULNERABLE: Values directly concatenated
        sql.append(String.join("', '", values.values()));
        sql.append("')");

        return sql.toString();
    }

    /**
     * VULNERABLE: UPDATE query builder with injection
     */
    public String buildUpdate(Map<String, String> updates, String whereField, String whereValue) {
        StringBuilder sql = new StringBuilder();
        sql.append("UPDATE ").append(table).append(" SET ");

        List<String> setParts = new ArrayList<>();
        for (Map.Entry<String, String> entry : updates.entrySet()) {
            // VULNERABLE: Both key and value are user-controlled
            setParts.add(entry.getKey() + " = '" + entry.getValue() + "'");
        }

        sql.append(String.join(", ", setParts));
        sql.append(" WHERE ").append(whereField).append(" = '").append(whereValue).append("'");

        return sql.toString();
    }

    /**
     * VULNERABLE: DELETE query builder
     */
    public String buildDelete(String whereField, String whereValue) {
        // VULNERABLE: Direct concatenation
        return "DELETE FROM " + table + " WHERE " + whereField + " = '" + whereValue + "'";
    }

    /**
     * VULNERABLE: UNION-based query
     */
    public String buildUnion(String otherQuery) {
        // VULNERABLE: Allows UNION injection
        return build() + " UNION " + otherQuery;
    }
}
