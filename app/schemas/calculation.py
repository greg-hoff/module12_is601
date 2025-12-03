from enum import Enum
from pydantic import BaseModel, Field, ConfigDict, model_validator, field_validator
from typing import List, Optional
from uuid import UUID
from datetime import datetime

class CalculationType(str, Enum):
    """Valid calculation types"""
    ADDITION = "addition"
    SUBTRACTION = "subtraction"
    MULTIPLICATION = "multiplication"
    DIVISION = "division"

class CalculationBase(BaseModel):
    type: CalculationType = Field(
        ...,
        description="Type of calculation (addition, subtraction, multiplication, division)",
        example="addition"
    )
    inputs: List[float] = Field(
        ...,
        description="List of numeric inputs for the calculation. Accepts integers, floats, or numeric strings.",
        example=[10.5, 3, 2],
        min_items=2
    )

    @field_validator("type", mode="before")
    @classmethod
    def validate_type(cls, v):
        allowed = {e.value for e in CalculationType}
        # Ensure v is a string and check (in lowercase) if it's allowed.
        if not isinstance(v, str) or v.lower() not in allowed:
            raise ValueError(f"Type must be one of: {', '.join(sorted(allowed))}")
        return v.lower()

    @field_validator("inputs", mode="before")
    @classmethod
    def check_inputs_is_list(cls, v):
        if not isinstance(v, list):
            raise ValueError("Input should be a valid list")
        
        # Validate and convert each element to float
        validated_inputs = []
        for i, item in enumerate(v):
            try:
                # Try to convert to float
                if isinstance(item, (int, float)):
                    validated_inputs.append(float(item))
                elif isinstance(item, str):
                    # Allow string numbers like "3.14"
                    validated_inputs.append(float(item))
                else:
                    raise ValueError(f"Input at position {i} must be a number, got {type(item).__name__}")
            except ValueError as e:
                if "could not convert" in str(e) or "invalid literal" in str(e):
                    raise ValueError(f"Input at position {i} must be a valid number, got '{item}'")
                raise e
        
        return validated_inputs

    @model_validator(mode='after')
    def validate_inputs(self) -> "CalculationBase":
        """Validate inputs based on calculation type"""
        if len(self.inputs) < 2:
            raise ValueError("At least two numbers are required for calculation")
        if self.type == CalculationType.DIVISION:
            # Prevent division by zero (skip the first value as numerator)
            if any(x == 0 for x in self.inputs[1:]):
                raise ValueError("Cannot divide by zero")
        return self

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "examples": [
                {"type": "addition", "inputs": [10.5, 3, 2]},
                {"type": "division", "inputs": [100, 2]}
            ]
        }
    )

class CalculationCreate(CalculationBase):
    """Schema for creating a new Calculation"""
    user_id: UUID = Field(
        ...,
        description="UUID of the user who owns this calculation",
        example="123e4567-e89b-12d3-a456-426614174000"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "addition",
                "inputs": [10.5, 3, 2],
                "user_id": "123e4567-e89b-12d3-a456-426614174000"
            }
        }
    )

class CalculationUpdate(BaseModel):
    """Schema for updating an existing Calculation"""
    inputs: Optional[List[float]] = Field(
        None,
        description="Updated list of numeric inputs for the calculation",
        example=[42, 7],
        min_items=2
    )

    @model_validator(mode='after')
    def validate_inputs(self) -> "CalculationUpdate":
        """Validate the inputs if they are being updated"""
        if self.inputs is not None and len(self.inputs) < 2:
            raise ValueError("At least two numbers are required for calculation")
        return self

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={"example": {"inputs": [42, 7]}}
    )

class CalculationResponse(CalculationBase):
    """Schema for reading a Calculation from the database"""
    id: UUID = Field(
        ...,
        description="Unique UUID of the calculation",
        example="123e4567-e89b-12d3-a456-426614174999"
    )
    user_id: UUID = Field(
        ...,
        description="UUID of the user who owns this calculation",
        example="123e4567-e89b-12d3-a456-426614174000"
    )
    created_at: datetime = Field(..., description="Time when the calculation was created")
    updated_at: datetime = Field(..., description="Time when the calculation was last updated")
    result: float = Field(
        ...,
        description="Result of the calculation",
        example=15.5
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174999",
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "type": "addition",
                "inputs": [10.5, 3, 2],
                "result": 15.5,
                "created_at": "2025-01-01T00:00:00",
                "updated_at": "2025-01-01T00:00:00"
            }
        }
    )
