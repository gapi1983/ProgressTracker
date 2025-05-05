using Microsoft.AspNetCore.Identity;

namespace ProgressTracker.Models
{
    public class ApplicationUser:IdentityUser<Guid>
    {
        // custom properties
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool TwoFactorSetupComplete { get; set; } = false;

        // navigational properties
        public virtual ICollection<TaskItem> TasksAssigned { get; set; }
        public virtual ICollection<TaskItem> TasksCreated { get; set; }
        public virtual ICollection<Comment> Comments { get; set; }
        
    }
}
