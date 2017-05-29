namespace Cmas.Infrastructure.Security
{
    /// <summary>
    /// Роли пользователей
    /// </summary>
    public enum Role
    {
        Unknown,

        /// <summary>
        /// Заказчик
        /// </summary>
        Customer,

        /// <summary>
        /// Подрядчик
        /// </summary>
        Contractor,

        /// <summary>
        /// Администратор
        /// </summary>
        Administrator
    }
}
