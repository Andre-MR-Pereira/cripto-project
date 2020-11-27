using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using FitnessTracker.Common.Models;
using FitnessTracker.Common.Utils;
using Microsoft.AspNetCore.Mvc;

namespace FitnessTrackerAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MetricsController : ControllerBase
    {
        private List<double> _distances = new List<double>();
        private List<double> _times = new List<double>();

        public MetricsController()
        {
            // Initialize context

            // Initialize key generator and encryptor

            // Initialize evaluator
        }

        [HttpGet]
        [Route("keys")]
        public ActionResult<KeysModel> GetKeys()
        {
            return null;
        }

        [HttpPost]
        [Route("")]
        public ActionResult AddRunItem([FromBody] RunItem request)
        {
            // Add AddRunItem code
            LogUtils.RunItemInfo("API", "AddRunItem", request);
            LogUtils.RunItemInfo("API", "AddRunItem", request, true);
            var distance = SEALUtils.Base64Decode(request.Distance);
            var time = SEALUtils.Base64Decode(request.Time);

            _distances.Add(Convert.ToInt32(distance));
            _times.Add(Convert.ToInt32(time));
            return Ok();
        }

        [HttpGet]
        [Route("")]
        public ActionResult<SummaryItem> GetMetrics()
        {
            var summaryItem = new SummaryItem
            {
                TotalRuns = SEALUtils.DoubleToBase64String(_distances.Count()),
                TotalDistance = SEALUtils.DoubleToBase64String(_distances.Sum()),
                TotalHours = SEALUtils.DoubleToBase64String(_times.Sum())
            };

            LogUtils.SummaryStatisticInfo("API", "GetMetrics", summaryItem);
            LogUtils.SummaryStatisticInfo("API", "GetMetrics", summaryItem, true);

            return summaryItem;
        }
    }
}