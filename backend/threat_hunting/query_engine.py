import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class EntityType(Enum):
    """Supported entity types for hunting"""
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    DNS = "dns"
    AUTHENTICATION = "authentication"
    USER = "user"
    ENDPOINT = "endpoint"
    ALERT = "alert"
    EVENT = "event"


class Operator(Enum):
    """Query operators"""
    EQUALS = "="
    NOT_EQUALS = "!="
    GREATER = ">"
    LESS = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT CONTAINS"
    STARTS_WITH = "STARTS WITH"
    ENDS_WITH = "ENDS WITH"
    MATCHES = "MATCHES"
    IN = "IN"
    NOT_IN = "NOT IN"
    IS_NULL = "IS NULL"
    IS_NOT_NULL = "IS NOT NULL"


@dataclass
class Condition:
    """Query condition"""
    field: str
    operator: Operator
    value: Any
    logical_op: Optional[str] = "AND"  # AND, OR, NOT


@dataclass
class CorrelationRule:
    """Event correlation rule"""
    entity_type: EntityType
    conditions: List[Condition]
    time_window_seconds: int


@dataclass
class AggregationRule:
    """Aggregation specification"""
    function: str  # count, sum, avg, min, max
    field: Optional[str] = None
    group_by: List[str] = None
    having_condition: Optional[Condition] = None


@dataclass
class ParsedQuery:
    """Parsed EDR-QL query"""
    entity_type: EntityType
    conditions: List[Condition]
    correlations: List[CorrelationRule]
    time_range_start: Optional[datetime]
    time_range_end: Optional[datetime]
    aggregation: Optional[AggregationRule]
    order_by: Optional[List[Tuple[str, str]]]  # [(field, direction)]
    limit: Optional[int]
    output_format: str  # json, csv, table


class QueryParser:
    """EDR-QL query parser"""
    
    def __init__(self):
        self.operators_map = {
            "=": Operator.EQUALS,
            "!=": Operator.NOT_EQUALS,
            ">=": Operator.GREATER_EQUAL,
            "<=": Operator.LESS_EQUAL,
            ">" : Operator.GREATER,
            "<": Operator.LESS,
            "CONTAINS": Operator.CONTAINS,
            "NOT CONTAINS": Operator.NOT_CONTAINS,
            "STARTS WITH": Operator.STARTS_WITH,
            "ENDS WITH": Operator.ENDS_WITH,
            "MATCHES": Operator.MATCHES,
            "IN": Operator.IN,
            "NOT IN": Operator.NOT_IN,
            "IS NULL": Operator.IS_NULL,
            "IS NOT NULL": Operator.IS_NOT_NULL,
        }
    
    def parse(self, query: str) -> ParsedQuery:
        """Parse EDR-QL query string"""
        query = query.strip()
        
        # Extract entity type
        entity_type = self._extract_entity_type(query)
        
        # Extract WHERE conditions
        conditions = self._extract_conditions(query)
        
        # Extract CORRELATE rules
        correlations = self._extract_correlations(query)
        
        # Extract TIMERANGE
        time_start, time_end = self._extract_time_range(query)
        
        # Extract AGGREGATE
        aggregation = self._extract_aggregation(query)
        
        # Extract ORDER BY
        order_by = self._extract_order_by(query)
        
        # Extract LIMIT
        limit = self._extract_limit(query)
        
        # Extract OUTPUT format
        output_format = self._extract_output_format(query)
        
        return ParsedQuery(
            entity_type=entity_type,
            conditions=conditions,
            correlations=correlations,
            time_range_start=time_start,
            time_range_end=time_end,
            aggregation=aggregation,
            order_by=order_by,
            limit=limit,
            output_format=output_format
        )
    
    def _extract_entity_type(self, query: str) -> EntityType:
        """Extract HUNT entity type"""
        match = re.search(r'HUNT\s+(\w+)', query, re.IGNORECASE)
        if not match:
            raise ValueError("Query must start with HUNT <entity_type>")
        
        entity_str = match.group(1).lower()
        try:
            return EntityType(entity_str)
        except ValueError:
            raise ValueError(f"Unknown entity type: {entity_str}")
    
    def _extract_conditions(self, query: str) -> List[Condition]:
        """Extract WHERE conditions"""
        match = re.search(r'WHERE\s+(.+?)(?:CORRELATE|TIMERANGE|AGGREGATE|ORDER BY|LIMIT|OUTPUT|$)', 
                         query, re.IGNORECASE | re.DOTALL)
        
        if not match:
            return []
        
        conditions_str = match.group(1).strip()
        return self._parse_conditions(conditions_str)
    
    def _parse_conditions(self, conditions_str: str) -> List[Condition]:
        """Parse condition string into Condition objects"""
        conditions = []
        
        # Split by AND/OR while preserving them
        parts = re.split(r'\s+(AND|OR)\s+', conditions_str, flags=re.IGNORECASE)
        
        current_logical_op = "AND"
        for i, part in enumerate(parts):
            part = part.strip()
            
            if part.upper() in ("AND", "OR"):
                current_logical_op = part.upper()
                continue
            
            # Parse individual condition
            condition = self._parse_single_condition(part)
            if condition:
                condition.logical_op = current_logical_op if i > 0 else None
                conditions.append(condition)
        
        return conditions
    
    def _parse_single_condition(self, cond_str: str) -> Optional[Condition]:
        """Parse single condition"""
        cond_str = cond_str.strip()
        
        # Try each operator
        for op_str, operator in self.operators_map.items():
            pattern = re.escape(op_str)
            match = re.search(rf'(\w+)\s+{pattern}\s+(.+)', cond_str, re.IGNORECASE)
            
            if match:
                field = match.group(1)
                value_str = match.group(2).strip()
                
                # Parse value
                value = self._parse_value(value_str, operator)
                
                return Condition(field=field, operator=operator, value=value)
        
        return None
    
    def _parse_value(self, value_str: str, operator: Operator) -> Any:
        """Parse condition value"""
        value_str = value_str.strip()
        
        # Handle IN/NOT IN lists
        if operator in (Operator.IN, Operator.NOT_IN):
            match = re.match(r'\((.+)\)', value_str)
            if match:
                items = [v.strip().strip('"\"') for v in match.group(1).split(',')]
                return items
        
        # Handle NULL checks
        if operator in (Operator.IS_NULL, Operator.IS_NOT_NULL):
            return None
        
        # Remove quotes
        if value_str.startswith(('"', "'")) and value_str.endswith(('"', "'")):
            return value_str[1:-1]
        
        # Try numeric
        try:
            if '.' in value_str:
                return float(value_str)
            return int(value_str)
        except ValueError:
            return value_str
    
    def _extract_correlations(self, query: str) -> List[CorrelationRule]:
        """Extract CORRELATE rules"""
        correlations = []
        
        matches = re.finditer(
            r'CORRELATE\s+(\w+)\s+WHERE\s+(.+?)\s+WITHIN\s+(\d+)(s|m|h|d)',
            query,
            re.IGNORECASE
        )
        
        for match in matches:
            entity_type = EntityType(match.group(1).lower())
            conditions_str = match.group(2)
            time_value = int(match.group(3))
            time_unit = match.group(4)
            
            # Convert to seconds
            time_seconds = self._convert_to_seconds(time_value, time_unit)
            
            # Parse conditions
            conditions = self._parse_conditions(conditions_str)
            
            correlations.append(CorrelationRule(
                entity_type=entity_type,
                conditions=conditions,
                time_window_seconds=time_seconds
            ))
        
        return correlations
    
    def _extract_time_range(self, query: str) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Extract TIMERANGE specification"""
        match = re.search(r'TIMERANGE\s+last\s+(\d+)\s*(h|d|w|m)', query, re.IGNORECASE)
        
        if match:
            value = int(match.group(1))
            unit = match.group(2).lower()
            
            now = datetime.utcnow()
            
            if unit == 'h':
                start = now - timedelta(hours=value)
            elif unit == 'd':
                start = now - timedelta(days=value)
            elif unit == 'w':
                start = now - timedelta(weeks=value)
            elif unit == 'm':
                start = now - timedelta(days=value * 30)  # Approximate
            else:
                start = now - timedelta(hours=24)
            
            return start, now
        
        return None, None
    
    def _extract_aggregation(self, query: str) -> Optional[AggregationRule]:
        """Extract AGGREGATE specification"""
        match = re.search(
            r'AGGREGATE\s+(\w+)\s*(?:\((\w*)\))?\s*(?:BY\s+([\w,\s]+))?(?:\s+HAVING\s+(.+?)(?:ORDER BY|LIMIT|OUTPUT|$))?',
            query,
            re.IGNORECASE | re.DOTALL
        )
        
        if match:
            function = match.group(1).lower()
            field = match.group(2) if match.group(2) else None
            
            group_by = None
            if match.group(3):
                group_by = [f.strip() for f in match.group(3).split(',')]
            
            having_condition = None
            if match.group(4):
                having_condition = self._parse_single_condition(match.group(4))
            
            return AggregationRule(
                function=function,
                field=field,
                group_by=group_by,
                having_condition=having_condition
            )
        
        return None
    
    def _extract_order_by(self, query: str) -> Optional[List[Tuple[str, str]]]:
        """Extract ORDER BY specification"""
        match = re.search(r'ORDER BY\s+([\w,\s]+)(?:\s+(ASC|DESC))?', query, re.IGNORECASE)
        
        if match:
            fields_str = match.group(1)
            direction = match.group(2).upper() if match.group(2) else "ASC"
            
            fields = [f.strip() for f in fields_str.split(',')]
            return [(f, direction) for f in fields]
        
        return None
    
    def _extract_limit(self, query: str) -> Optional[int]:
        """Extract LIMIT specification"""
        match = re.search(r'LIMIT\s+(\d+)', query, re.IGNORECASE)
        return int(match.group(1)) if match else None
    
    def _extract_output_format(self, query: str) -> str:
        """Extract OUTPUT format"""
        match = re.search(r'OUTPUT\s+(\w+)', query, re.IGNORECASE)
        return match.group(1).lower() if match else "json"
    
    def _convert_to_seconds(self, value: int, unit: str) -> int:
        """Convert time value to seconds"""
        unit = unit.lower()
        if unit == 's':
            return value
        elif unit == 'm':
            return value * 60
        elif unit == 'h':
            return value * 3600
        elif unit == 'd':
            return value * 86400
        return value


class QueryExecutor:
    """Execute parsed EDR-QL queries against database"""
    
    def __init__(self, db_session):
        self.db = db_session
        self.entity_table_map = {
            EntityType.PROCESS: "edr_process_events",
            EntityType.FILE: "edr_file_events",
            EntityType.NETWORK: "edr_network_events",
            EntityType.REGISTRY: "edr_registry_events",
            EntityType.DNS: "edr_dns_events",
            EntityType.AUTHENTICATION: "edr_auth_events",
            EntityType.ALERT: "alerts",
        }
    
    def execute(self, parsed_query: ParsedQuery) -> Dict[str, Any]:
        """Execute parsed query and return results"""
        start_time = datetime.utcnow()
        
        # Build SQL query
        sql_query = self._build_sql(parsed_query)
        
        # Execute
        results = self.db.execute(sql_query).fetchall()
        
        # Apply correlations (post-processing)
        if parsed_query.correlations:
            results = self._apply_correlations(results, parsed_query)
        
        # Format output
        formatted_results = self._format_results(
            results,
            parsed_query.output_format
        )
        
        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return {
            "status": "success",
            "results": formatted_results,
            "count": len(formatted_results),
            "execution_time_ms": round(execution_time, 2)
        }
    
    def _build_sql(self, parsed_query: ParsedQuery) -> str:
        """Build SQL query from parsed EDR-QL"""
        table_name = self.entity_table_map.get(parsed_query.entity_type)
        
        if not table_name:
            raise ValueError(f"Unsupported entity type: {parsed_query.entity_type}")
        
        # SELECT clause
        if parsed_query.aggregation:
            select_clause = self._build_aggregation_select(parsed_query.aggregation)
        else:
            select_clause = "*"
        
        # FROM clause
        from_clause = table_name
        
        # WHERE clause
        where_clause = self._build_where_clause(parsed_query.conditions)
        
        # Time range
        if parsed_query.time_range_start:
            time_condition = f"timestamp >= '{parsed_query.time_range_start.isoformat()}'"
            if where_clause:
                where_clause += f" AND {time_condition}"
            else:
                where_clause = time_condition
        
        if parsed_query.time_range_end:
            time_condition = f"timestamp <= '{parsed_query.time_range_end.isoformat()}'"
            if where_clause:
                where_clause += f" AND {time_condition}"
            else:
                where_clause = time_condition
        
        # GROUP BY clause
        group_by_clause = ""
        if parsed_query.aggregation and parsed_query.aggregation.group_by:
            group_by_clause = f"GROUP BY {', '.join(parsed_query.aggregation.group_by)}"
        
        # HAVING clause
        having_clause = ""
        if parsed_query.aggregation and parsed_query.aggregation.having_condition:
            having_clause = f"HAVING {self._build_condition_sql(parsed_query.aggregation.having_condition)}"
        
        # ORDER BY clause
        order_by_clause = ""
        if parsed_query.order_by:
            order_parts = [f"{field} {direction}" for field, direction in parsed_query.order_by]
            order_by_clause = f"ORDER BY {', '.join(order_parts)}"
        
        # LIMIT clause
        limit_clause = ""
        if parsed_query.limit:
            limit_clause = f"LIMIT {parsed_query.limit}"
        
        # Assemble query
        sql_parts = [f"SELECT {select_clause} FROM {from_clause}"]
        if where_clause:
            sql_parts.append(f"WHERE {where_clause}")
        if group_by_clause:
            sql_parts.append(group_by_clause)
        if having_clause:
            sql_parts.append(having_clause)
        if order_by_clause:
            sql_parts.append(order_by_clause)
        if limit_clause:
            sql_parts.append(limit_clause)
        
        return " ".join(sql_parts)
    
    def _build_where_clause(self, conditions: List[Condition]) -> str:
        """Build WHERE clause from conditions"""
        if not conditions:
            return ""
        
        clause_parts = []
        for condition in conditions:
            sql_condition = self._build_condition_sql(condition)
            
            if condition.logical_op and clause_parts:
                clause_parts.append(condition.logical_op)
            
            clause_parts.append(sql_condition)
        
        return " ".join(clause_parts)
    
    def _build_condition_sql(self, condition: Condition) -> str:
        """Build SQL for single condition"""
        field = condition.field
        op = condition.operator
        value = condition.value
        
        if op == Operator.EQUALS:
            return f"{field} = '{value}'"
        elif op == Operator.NOT_EQUALS:
            return f"{field} != '{value}'"
        elif op == Operator.GREATER:
            return f"{field} > {value}"
        elif op == Operator.LESS:
            return f"{field} < {value}"
        elif op == Operator.GREATER_EQUAL:
            return f"{field} >= {value}"
        elif op == Operator.LESS_EQUAL:
            return f"{field} <= {value}"
        elif op == Operator.CONTAINS:
            return f"{field} LIKE '%{value}%'"
        elif op == Operator.NOT_CONTAINS:
            return f"{field} NOT LIKE '%{value}%'"
        elif op == Operator.STARTS_WITH:
            return f"{field} LIKE '{value}%'"
        elif op == Operator.ENDS_WITH:
            return f"{field} LIKE '%{value}'"
        elif op == Operator.MATCHES:
            return f"{field} ~ '{value}'"  # PostgreSQL regex
        elif op == Operator.IN:
            values_str = "', '".join(str(v) for v in value)
            return f"{field} IN ('{values_str}')"
        elif op == Operator.NOT_IN:
            values_str = "', '".join(str(v) for v in value)
            return f"{field} NOT IN ('{values_str}')"
        elif op == Operator.IS_NULL:
            return f"{field} IS NULL"
        elif op == Operator.IS_NOT_NULL:
            return f"{field} IS NOT NULL"
        
        return ""
    
    def _build_aggregation_select(self, agg: AggregationRule) -> str:
        """Build SELECT clause for aggregation"""
        func = agg.function.upper()
        
        if agg.group_by:
            group_fields = ", ".join(agg.group_by)
            if agg.field:
                return f"{group_fields}, {func}({agg.field}) as {agg.function}"
            else:
                return f"{group_fields}, {func}(*) as {agg.function}"
        else:
            if agg.field:
                return f"{func}({agg.field}) as {agg.function}"
            else:
                return f"{func}(*) as {agg.function}"
    
    def _apply_correlations(self, results: List, parsed_query: ParsedQuery) -> List:
        """Apply correlation rules (simplified implementation)"""
        # This is a simplified version - production would need more sophisticated correlation
        logger.info(f"Applying {len(parsed_query.correlations)} correlation rules")
        return results
    
    def _format_results(self, results: List, output_format: str) -> List[Dict]:
        """Format query results"""
        formatted = []
        for row in results:
            formatted.append(dict(row))
        return formatted


class ThreatHuntingEngine:
    """Main threat hunting engine"""
    
    def __init__(self, db_session):
        self.parser = QueryParser()
        self.executor = QueryExecutor(db_session)
    
    def hunt(self, query: str) -> Dict[str, Any]:
        """Execute threat hunting query"""
        try:
            # Parse query
            parsed_query = self.parser.parse(query)
            
            # Execute
            results = self.executor.execute(parsed_query)
            
            results["query"] = query
            return results
            
        except Exception as e:
            logger.error(f"Hunt query failed: {e}", exc_info=True)
            return {
                "status": "error",
                "error": str(e),
                "query": query
            }
    
    def validate_query(self, query: str) -> Dict[str, Any]:
        """Validate query syntax without executing"""
        try:
            parsed_query = self.parser.parse(query)
            return {
                "status": "valid",
                "entity_type": parsed_query.entity_type.value,
                "conditions_count": len(parsed_query.conditions),
                "correlations_count": len(parsed_query.correlations),
                "has_aggregation": parsed_query.aggregation is not None
            }
        except Exception as e:
            return {
                "status": "invalid",
                "error": str(e)
            }
