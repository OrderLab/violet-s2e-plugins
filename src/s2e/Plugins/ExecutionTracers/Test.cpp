///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement
///

//#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
//#include <s2e/Utils.h>
//#include <s2e/Plugins/Core/BaseInstructions.h>
//#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
//#include <stdio.h>
//#include <TraceEntries.pb.h>
#include "Test.h"

using namespace std;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TestP, "hahahahhaha", "TestP",);

void TestP::initialize() {
		//printf ("Initialize\n");
  //m_tracer = s2e()->getPlugin<ExecutionTracer>();
  //s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
  //    sigc::mem_fun(*this, &FileIOTracer::onTranslateSpecialInstructionEnd));
}


}
}
