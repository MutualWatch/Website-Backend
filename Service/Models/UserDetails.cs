using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.Models
{
    public class UserDetails
    {
        [Required]
        public string Password { get; set; }

        [Required]
        public string Email { get; set; }

        public string Firstname { get; set; }

        public string Lastname { get; set; }

        [Required]
        public UserType UserType { get; set; }
    }
}
