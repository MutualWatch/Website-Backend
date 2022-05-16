using System;
using System.Collections.Generic;

namespace Service.DbModels
{
    public partial class RefreshValue
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public string? RefreshToken { get; set; }
    }
}
