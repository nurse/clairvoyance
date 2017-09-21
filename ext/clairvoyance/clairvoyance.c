#include "clairvoyance.h"

VALUE rb_mClairvoyance;

void
Init_clairvoyance(void)
{
  rb_mClairvoyance = rb_define_module("Clairvoyance");
}
