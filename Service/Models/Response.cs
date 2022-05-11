using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Service.ViewModels
{
    public class Response
    {
        public bool Success { get; set; }
        public object? Data { get; set; }
        public string? Message { get; set; }
        public error error { get; set; }

        public override string ToString()
        {
            return JsonSerializer.Serialize(this);
        }
        public Response()
        {
            error = new error();
        }
        public Response(MESSAGE message, bool IsSuccess = true)
        {
            Success = IsSuccess;
            Message = GetEnumDescription(message);
        }

        public Response(string message, bool IsSuccess = true)
        {
            Message = message;
            Success = IsSuccess;
        }

        public void UpdateStatus(MESSAGE message, bool IsSuccess = false)
        {
            Success = IsSuccess;
            Message = GetEnumDescription(message);
        }

        public void UpdateStatus(string message, bool IsSuccess = false)
        {
            Message = message;
            Success = IsSuccess;
        }

        public string GetEnumDescription(Enum enumValue)
        {
            var fieldInfo = enumValue.GetType().GetField(enumValue.ToString());

            var descriptionAttributes = (DescriptionAttribute[])fieldInfo.GetCustomAttributes(typeof(DescriptionAttribute), false);

            return descriptionAttributes.Length > 0 ? descriptionAttributes[0].Description : enumValue.ToString();
        }
       
    }
    public class error
    {
        public long errorCode { get; set; }
        public string errorMessage { get; set; }
    }
    public enum MESSAGE : int
    {
        [Description("Record saved successfully")]
        SAVED = 1,

        [Description("Record updated successfully")]
        UPDATED = 2,

        [Description("Record deleted successfully")]
        DELETED = 3,

        [Description("Record loaded successfully")]
        LOADED = 4,

        [Description("Data not found")]
        DATA_NOT_FOUND = 5,

        [Description("Already used,so you can not delete")]
        ALREADY_USED = 6,

        [Description("User logged out successfully")]
        LOGGED_OUT = 7,

        [Description("Record publish successfully")]
        PUBLISH = 8,
    }
}