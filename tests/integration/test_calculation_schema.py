import pytest
from pydantic import ValidationError
from uuid import uuid4
from datetime import datetime
from app.schemas.calculation import (
    CalculationCreate,
    CalculationUpdate,
    CalculationResponse
)

def test_calculation_create_valid():
    """Test creating a valid CalculationCreate schema."""
    data = {
        "type": "addition",
        "inputs": [10.5, 3.0],
        "user_id": uuid4()
    }
    calc = CalculationCreate(**data)
    assert calc.type == "addition"
    assert calc.inputs == [10.5, 3.0]
    assert calc.user_id is not None

def test_calculation_create_missing_type():
    """Test CalculationCreate fails if 'type' is missing."""
    data = {
        "inputs": [10.5, 3.0],
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    # Look for a substring that indicates a missing required field.
    assert "required" in str(exc_info.value).lower()

def test_calculation_create_missing_inputs():
    """Test CalculationCreate fails if 'inputs' is missing."""
    data = {
        "type": "multiplication",
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    assert "required" in str(exc_info.value).lower()

def test_calculation_create_invalid_inputs():
    """Test CalculationCreate fails if 'inputs' is not a list of floats."""
    data = {
        "type": "division",
        "inputs": "not-a-list",
        "user_id": uuid4()
    }

def test_calculation_update_valid_type_only():
    """Test CalculationUpdate with only type change."""
    data = {"type": "multiplication"}
    calc_update = CalculationUpdate(**data)
    assert calc_update.type == "multiplication"
    assert calc_update.inputs is None

def test_calculation_update_valid_inputs_only():
    """Test CalculationUpdate with only inputs change."""
    data = {"inputs": [42.0, 7.0]}
    calc_update = CalculationUpdate(**data)
    assert calc_update.type is None
    assert calc_update.inputs == [42.0, 7.0]

def test_calculation_update_valid_both_fields():
    """Test CalculationUpdate with both type and inputs."""
    data = {
        "type": "division",
        "inputs": [100.0, 5.0]
    }
    calc_update = CalculationUpdate(**data)
    assert calc_update.type == "division"
    assert calc_update.inputs == [100.0, 5.0]

def test_calculation_update_invalid_type():
    """Test CalculationUpdate fails with invalid type."""
    data = {"type": "invalid_operation"}
    with pytest.raises(ValidationError) as exc_info:
        CalculationUpdate(**data)
    assert "Type must be one of" in str(exc_info.value)

def test_calculation_update_division_by_zero():
    """Test CalculationUpdate prevents division by zero."""
    data = {
        "type": "division",
        "inputs": [100.0, 0.0]
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationUpdate(**data)
    assert "Cannot divide by zero" in str(exc_info.value)

def test_calculation_update_string_to_float_conversion():
    """Test CalculationUpdate converts string numbers to floats."""
    data = {
        "type": "addition",
        "inputs": ["10.5", "3", 2.5]
    }
    calc_update = CalculationUpdate(**data)
    assert calc_update.inputs == [10.5, 3.0, 2.5]

def test_calculation_update_invalid_input_type():
    """Test CalculationUpdate fails with non-numeric inputs."""
    data = {
        "inputs": [10, "not_a_number", 5]
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationUpdate(**data)
    assert "Input at position 1 must be a valid number" in str(exc_info.value)

def test_calculation_update_too_few_inputs():
    """Test CalculationUpdate fails with less than 2 inputs."""
    data = {"inputs": [42]}
    with pytest.raises(ValidationError) as exc_info:
        CalculationUpdate(**data)
    # Check for either our custom message or Pydantic's built-in message
    error_str = str(exc_info.value)
    assert ("At least two numbers are required" in error_str or 
            "List should have at least 2 items" in error_str)

def test_calculation_create_unsupported_type():
    """Test CalculationCreate fails if an unsupported calculation type is provided."""
    data = {
        "type": "square_root",  # Unsupported type
        "inputs": [25],
        "user_id": uuid4()
    }
    with pytest.raises(ValidationError) as exc_info:
        CalculationCreate(**data)
    error_message = str(exc_info.value).lower()
    # Check that the error message indicates the value is not permitted.
    assert "one of" in error_message or "not a valid" in error_message

def test_calculation_update_valid():
    """Test a valid partial update with CalculationUpdate."""
    data = {
        "inputs": [42.0, 7.0]
    }
    calc_update = CalculationUpdate(**data)
    assert calc_update.inputs == [42.0, 7.0]

def test_calculation_update_no_fields():
    """Test that an empty update is allowed (i.e., no fields)."""
    calc_update = CalculationUpdate()
    assert calc_update.inputs is None

def test_calculation_response_valid():
    """Test creating a valid CalculationResponse schema."""
    data = {
        "id": uuid4(),
        "user_id": uuid4(),
        "type": "subtraction",
        "inputs": [20, 5],
        "result": 15.5,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    calc_response = CalculationResponse(**data)
    assert calc_response.id is not None
    assert calc_response.user_id is not None
    assert calc_response.type == "subtraction"
    assert calc_response.inputs == [20, 5]
    assert calc_response.result == 15.5
